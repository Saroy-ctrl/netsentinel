"""M1-03: corrected CSE-CIC-IDS2018 -> canonical cleaned parquet (one file per day).

    python -m ml.data.adapters.cic2018                       # all 10 days -> data/processed/cic2018/
    python -m ml.data.adapters.cic2018 --days Friday-02-03-2018 --max-chunks 2   # quick smoke run

What it does, per day file, streaming straight out of the zip (36 GB never touches disk):
  * parse in ~400 MB chunks from memory (arrow's streaming reader on a zip member is ~40x slower)
  * rename columns to snake_case, ts -> timestamp[us] (UTC), features -> float32
  * label -> AttackFamily; rows with `Attempted Category != -1` -> BENIGN (dataset authors' advice)
  * +/-Infinity -> NaN. Nothing is imputed or zero-filled here; NaN/Inf/negative counts are reported per column
  * drop exact duplicates (same features + dst_port + protocol + family), globally across days, keep first
Writes clean_report.json with every count, so the numbers in docs/data_profile.md are reproducible.

Canonical columns: day, row, ts, src_ip, src_port, dst_ip, dst_port, protocol, family, tool, attempted, <81 features>.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ZIP = ROOT / "data" / "raw" / "cic2018" / "CSECICIDS2018_improved.zip"
DEFAULT_OUT = ROOT / "data" / "processed" / "cic2018"

RAW_COLUMNS = (
    "id,Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Total Fwd Packet,"
    "Total Bwd packets,Total Length of Fwd Packet,Total Length of Bwd Packet,Fwd Packet Length Max,"
    "Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,Bwd Packet Length Max,"
    "Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,Flow Bytes/s,Flow Packets/s,"
    "Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,"
    "Fwd IAT Max,Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,"
    "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd RST Flags,Bwd RST Flags,"
    "Fwd Header Length,Bwd Header Length,Fwd Packets/s,Bwd Packets/s,Packet Length Min,Packet Length Max,"
    "Packet Length Mean,Packet Length Std,Packet Length Variance,FIN Flag Count,SYN Flag Count,"
    "RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,"
    "Down/Up Ratio,Average Packet Size,Fwd Segment Size Avg,Bwd Segment Size Avg,Fwd Bytes/Bulk Avg,"
    "Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,Bwd Bytes/Bulk Avg,Bwd Packet/Bulk Avg,Bwd Bulk Rate Avg,"
    "Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,FWD Init Win Bytes,"
    "Bwd Init Win Bytes,Fwd Act Data Pkts,Fwd Seg Size Min,Active Mean,Active Std,Active Max,Active Min,"
    "Idle Mean,Idle Std,Idle Max,Idle Min,ICMP Code,ICMP Type,Total TCP Flow Time,Label,Attempted Category"
).split(",")

SKIP = {"id", "Flow ID"}
META_RAW = {"Src IP": "src_ip", "Src Port": "src_port", "Dst IP": "dst_ip", "Dst Port": "dst_port",
            "Protocol": "protocol", "Timestamp": "ts"}
NON_FEATURE = SKIP | set(META_RAW) | {"Label", "Attempted Category"}
INT_COLS = {"Src Port", "Dst Port", "Protocol", "Attempted Category"}
STR_COLS = {"Src IP", "Dst IP", "Timestamp", "Label"}


def snake(name: str) -> str:
    return re.sub(r"[^0-9a-z]+", "_", name.strip().replace("/", " per ").lower()).strip("_")


FEATURE_RAW = [c for c in RAW_COLUMNS if c not in NON_FEATURE]
FEATURES = [snake(c) for c in FEATURE_RAW]
assert len(set(FEATURES)) == len(FEATURES) == 81, "feature name collision after snake_case"

LABEL_TO_FAMILY = {
    "BENIGN": "BENIGN", "Botnet Ares": "Botnet",
    "DDoS-HOIC": "DDoS", "DDoS-LOIC-HTTP": "DDoS", "DDoS-LOIC-UDP": "DDoS",
    "DoS GoldenEye": "DoS", "DoS Hulk": "DoS", "DoS Slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "SSH-BruteForce": "BruteForce", "FTP-BruteForce": "BruteForce",
    "Infiltration - Communication Victim Attacker": "Infiltration",
    "Infiltration - Dropbox Download": "Infiltration", "Infiltration - NMAP Portscan": "Infiltration",
    "Web Attack - Brute Force": "WebAttack", "Web Attack - SQL": "WebAttack", "Web Attack - XSS": "WebAttack",
}
ATTEMPTED_SUFFIX = " - Attempted"
FAMILY_CODE = {f: i for i, f in enumerate(sorted(set(LABEL_TO_FAMILY.values())))}

COLUMN_TYPES = (
    {c: pa.float64() for c in FEATURE_RAW}
    | {c: pa.int32() for c in INT_COLS}
    | {c: pa.string() for c in STR_COLS}
)


def families(labels: pd.Series, attempted: np.ndarray) -> pd.Series:
    """Label -> family. `X - Attempted` labels are always the attack's name + suffix; the flag decides."""
    base = labels.str.removesuffix(ATTEMPTED_SUFFIX)
    unknown = sorted(set(base.unique()) - set(LABEL_TO_FAMILY))
    if unknown:
        raise ValueError(f"unmapped labels: {unknown}")
    fam = base.map(LABEL_TO_FAMILY)
    fam[attempted] = "BENIGN"
    return fam


def iter_chunks(zf: zipfile.ZipFile, member: str, chunk_bytes: int):
    """Yield arrow tables of ~chunk_bytes of CSV each, parsed from memory."""
    opts = pacsv.ConvertOptions(column_types=COLUMN_TYPES, include_columns=[c for c in RAW_COLUMNS if c not in SKIP])
    with zf.open(member) as f:
        header = f.readline()
        got = header.decode().strip().split(",")
        if got != RAW_COLUMNS:
            raise ValueError(f"{member}: unexpected header, differing columns: {sorted(set(got) ^ set(RAW_COLUMNS))}")
        leftover = b""
        while True:
            block = f.read(chunk_bytes)
            if not block:
                if leftover.strip():
                    yield pacsv.read_csv(pa.BufferReader(header + leftover), convert_options=opts)
                return
            buf = leftover + block
            cut = buf.rfind(b"\n") + 1
            body, leftover = buf[:cut], buf[cut:]
            if body:
                yield pacsv.read_csv(pa.BufferReader(header + body), convert_options=opts)


class Deduper:
    """Global exact-duplicate filter on a 64-bit row hash (collision odds ~1e-3 over 6e7 rows; reported)."""

    def __init__(self) -> None:
        self.seen = np.empty(0, dtype=np.uint64)

    def keep_mask(self, h: np.ndarray) -> np.ndarray:
        dup = pd.Series(h).duplicated().to_numpy()
        if len(self.seen):
            pos = np.minimum(np.searchsorted(self.seen, h), len(self.seen) - 1)
            dup = dup | (self.seen[pos] == h)  # not |=: pandas >= 3 hands back read-only arrays
        keep = ~dup
        self.seen = np.concatenate([self.seen, np.unique(h[keep])])
        self.seen.sort(kind="stable")  # two sorted runs -> near-linear merge
        return keep


def clean_chunk(tbl: pa.Table, day: str, row0: int, dd: Deduper, rep: dict) -> pa.Table:
    n = tbl.num_rows
    X = np.column_stack([tbl[c].to_numpy(zero_copy_only=False) for c in FEATURE_RAW])
    inf, nan, neg = np.isinf(X), np.isnan(X), X < 0
    for name, a, b, c in zip(FEATURES, inf.sum(0), nan.sum(0), neg.sum(0), strict=True):
        if a or b or c:
            r = rep["columns"].setdefault(name, {"inf": 0, "nan": 0, "neg": 0})
            r["inf"] += int(a); r["nan"] += int(b); r["neg"] += int(c)  # noqa: E702
    rep["rows_with_nonfinite"] += int((inf | nan).any(1).sum())
    X[inf] = np.nan
    X32 = X.astype(np.float32)

    attempted = tbl["Attempted Category"].to_numpy() != -1
    labels = tbl["Label"].to_pandas()
    fam = families(labels, attempted)
    key = pd.DataFrame(X32, columns=FEATURES)
    key["dst_port"] = tbl["Dst Port"].to_numpy()
    key["protocol"] = tbl["Protocol"].to_numpy()
    key["fam"] = fam.map(FAMILY_CODE).to_numpy(dtype=np.int16)
    keep = dd.keep_mask(pd.util.hash_pandas_object(key, index=False).to_numpy())

    rep["rows_in"] += n
    rep["attempted_to_benign"] += int(attempted.sum())
    rep["duplicates_removed"] += int((~keep).sum())
    for f, k in Counter(fam[~keep]).items():
        rep["duplicates_by_family"][f] += k
    for f, k in Counter(fam[keep]).items():
        rep["family_counts"][f] += k

    cols = {
        "day": pa.array([day] * n), "row": pa.array(np.arange(row0, row0 + n, dtype=np.int32)),
        "ts": pc.cast(tbl["Timestamp"], pa.timestamp("us")),
        "src_ip": tbl["Src IP"], "src_port": tbl["Src Port"], "dst_ip": tbl["Dst IP"], "dst_port": tbl["Dst Port"],
        "protocol": pc.cast(tbl["Protocol"], pa.int16()),
        "family": pa.array(fam.to_numpy()), "tool": tbl["Label"], "attempted": pa.array(attempted),
    }
    for i, name in enumerate(FEATURES):
        cols[name] = pa.array(X32[:, i])
    out = pa.table(cols).filter(pa.array(keep))
    if out.num_rows:
        ts = out["ts"]
        lo, hi = pc.min(ts).as_py(), pc.max(ts).as_py()
        rep["ts_min"] = min(filter(None, [rep["ts_min"], lo.isoformat()])) if lo else rep["ts_min"]
        rep["ts_max"] = max(filter(None, [rep["ts_max"], hi.isoformat()])) if hi else rep["ts_max"]
    return out


def new_report() -> dict:
    return {"rows_in": 0, "rows_kept": 0, "attempted_to_benign": 0, "duplicates_removed": 0,
            "rows_with_nonfinite": 0, "duplicates_by_family": Counter(), "family_counts": Counter(),
            "columns": {}, "ts_min": None, "ts_max": None, "seconds": 0.0}


def process(zip_path: Path, out_dir: Path, days: list[str] | None, chunk_mb: int, max_chunks: int | None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    dd = Deduper()
    report: dict = {"source": zip_path.name, "features": FEATURES, "days": {}}
    with zipfile.ZipFile(zip_path) as zf:
        members = sorted((m for m in zf.namelist() if m.endswith(".csv")),
                         key=lambda m: m.removesuffix(".csv").split("-")[-3:][::-1])  # chronological
        for member in members:
            day = member.removesuffix(".csv")
            if days and day not in days:
                continue
            rep, t0, row0, writer = new_report(), time.time(), 0, None
            for i, tbl in enumerate(iter_chunks(zf, member, chunk_mb << 20)):
                if max_chunks and i >= max_chunks:
                    break
                out = clean_chunk(tbl, day, row0, dd, rep)
                row0 += tbl.num_rows
                rep["rows_kept"] += out.num_rows
                if writer is None:
                    writer = pq.ParquetWriter(out_dir / f"{day}.parquet", out.schema, compression="zstd")
                writer.write_table(out)
                print(f"\r  {day}: {row0:>9,} rows in, {rep['rows_kept']:>9,} kept", end="", flush=True)
            if writer:
                writer.close()
            rep["seconds"] = round(time.time() - t0, 1)
            print(f"  ({rep['seconds']} s)")
            report["days"][day] = rep
    tot = lambda k: sum(d[k] for d in report["days"].values())  # noqa: E731
    report["totals"] = {k: tot(k) for k in ("rows_in", "rows_kept", "attempted_to_benign", "duplicates_removed",
                                            "rows_with_nonfinite")}
    (out_dir / "clean_report.json").write_text(json.dumps(report, indent=1, default=dict) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--zip", type=Path, default=DEFAULT_ZIP)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--days", nargs="*", help="e.g. Friday-02-03-2018 (default: all)")
    ap.add_argument("--chunk-mb", type=int, default=400)
    ap.add_argument("--max-chunks", type=int, help="smoke-test: stop after N chunks per day")
    a = ap.parse_args()
    r = process(a.zip, a.out, a.days, a.chunk_mb, a.max_chunks)
    print(json.dumps(r["totals"], indent=1))
