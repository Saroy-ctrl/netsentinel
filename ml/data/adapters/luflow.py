"""M1-09: LUFlow daily zips -> canonical cleaned parquet (one file per day), same layout as the 2018 adapter.

    python -m ml.data.adapters.luflow                  # all downloaded days -> data/processed/luflow/
    python -m ml.data.adapters.luflow --max-days 2     # smoke run

LUFlow facts that shape the code (measured, data/README.md):
  * 16 columns; the CSV calls the inter-packet time `avg_ipt` (the repo README says `mean_ipt`)
  * src_ip / dest_ip are integers (anonymised to the owning network) -> strings, metadata only
  * time_start / time_end are MICROSECONDS since the epoch (UTC)
  * dest_port / src_port can be blank (port-less protocols) -> -1
  * labels: benign / malicious / outlier. `outlier` = abnormal but unexplained; it is kept (family "Outlier") but
    must never be used as a supervised class. It is the novelty detector's showcase.
Same policy as 2018: +/-Inf -> NaN (counted), no imputation, exact duplicates (features + dst_port + protocol +
label) removed globally, clean_report.json with every count.
"""

from __future__ import annotations

import argparse
import json
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

from ml.data.adapters.cic2018 import Deduper

ROOT = Path(__file__).resolve().parents[3]
RAW = ROOT / "data" / "raw" / "luflow"
DEFAULT_OUT = ROOT / "data" / "processed" / "luflow"

RAW_COLUMNS = {"avg_ipt", "bytes_in", "bytes_out", "dest_ip", "dest_port", "entropy", "num_pkts_out", "num_pkts_in",
               "proto", "src_ip", "src_port", "time_end", "time_start", "total_entropy", "label", "duration"}
FEATURES = ["avg_ipt", "bytes_in", "bytes_out", "num_pkts_in", "num_pkts_out", "entropy", "total_entropy", "duration"]
RAW_NAMES = {f: f for f in FEATURES} | {"protocol": "proto", "dst_port": "dest_port"}
FAMILY = {"benign": "BENIGN", "malicious": "Malicious", "outlier": "Outlier"}
FAMILY_CODE = {f: i for i, f in enumerate(sorted(FAMILY.values()))}

COLUMN_TYPES = (
    {c: pa.float64() for c in ("avg_ipt", "entropy", "total_entropy", "duration", "dest_port", "src_port")}
    | {c: pa.int64() for c in ("bytes_in", "bytes_out", "num_pkts_in", "num_pkts_out", "proto", "time_start",
                               "time_end", "src_ip", "dest_ip")}
    | {"label": pa.string()}
)


def clean_day(tbl: pa.Table, day: str, dd: Deduper, rep: dict) -> pa.Table:
    got = set(tbl.column_names)
    if got != RAW_COLUMNS:
        raise ValueError(f"{day}: unexpected columns, differing: {sorted(got ^ RAW_COLUMNS)}")
    n = tbl.num_rows
    X = np.column_stack([tbl[c].to_numpy(zero_copy_only=False) for c in FEATURES]).astype(np.float64)
    inf, nan, neg = np.isinf(X), np.isnan(X), X < 0
    for name, a, b, c in zip(FEATURES, inf.sum(0), nan.sum(0), neg.sum(0), strict=True):
        if a or b or c:
            r = rep["columns"].setdefault(name, {"inf": 0, "nan": 0, "neg": 0})
            r["inf"] += int(a); r["nan"] += int(b); r["neg"] += int(c)  # noqa: E702
    rep["rows_with_nonfinite"] += int((inf | nan).any(1).sum())
    X[inf] = np.nan
    X32 = X.astype(np.float32)

    labels = tbl["label"].to_pandas()
    unknown = sorted(set(labels.unique()) - set(FAMILY))
    if unknown:
        raise ValueError(f"unmapped labels: {unknown}")
    fam = labels.map(FAMILY)
    dst_port = pc.fill_null(tbl["dest_port"], -1).cast(pa.int32())
    src_port = pc.fill_null(tbl["src_port"], -1).cast(pa.int32())
    key = pd.DataFrame(X32, columns=FEATURES)
    key["dst_port"] = dst_port.to_numpy()
    key["protocol"] = tbl["proto"].to_numpy()
    key["fam"] = fam.map(FAMILY_CODE).to_numpy(dtype=np.int16)
    keep = dd.keep_mask(pd.util.hash_pandas_object(key, index=False).to_numpy())

    rep["rows_in"] += n
    rep["duplicates_removed"] += int((~keep).sum())
    for f, k in Counter(fam[~keep]).items():
        rep["duplicates_by_family"][f] += k
    for f, k in Counter(fam[keep]).items():
        rep["family_counts"][f] += k

    ts = pc.cast(tbl["time_start"], pa.timestamp("us"))
    cols = {
        "day": pa.array([day] * n), "row": pa.array(np.arange(n, dtype=np.int32)),
        "period": pa.array(tbl["time_start"].to_numpy().astype("datetime64[us]").astype("datetime64[M]").astype(str)),
        "ts": ts,
        "src_ip": pc.cast(tbl["src_ip"], pa.string()), "src_port": src_port,
        "dst_ip": pc.cast(tbl["dest_ip"], pa.string()), "dst_port": dst_port,
        "protocol": pc.cast(tbl["proto"], pa.int16()),
        "family": pa.array(fam.to_numpy()), "tool": tbl["label"],
    }
    for i, name in enumerate(FEATURES):
        cols[name] = pa.array(X32[:, i])
    return pa.table(cols).filter(pa.array(keep))


def process(raw: Path, out_dir: Path, max_days: int | None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    dd = Deduper()
    report: dict = {"features": FEATURES, "days": {}}
    zips = sorted(raw.glob("*/*/*.zip"))
    if max_days:
        zips = zips[:max_days]
    for zpath in zips:
        with zipfile.ZipFile(zpath) as zf:
            (member,) = [m for m in zf.namelist() if m.endswith(".csv")]
            day = member.removesuffix(".csv")
            t0 = time.time()
            opts = pacsv.ConvertOptions(column_types=COLUMN_TYPES)
            tbl = pacsv.read_csv(pa.BufferReader(zf.read(member)), convert_options=opts)
        rep = {"rows_in": 0, "rows_kept": 0, "duplicates_removed": 0, "rows_with_nonfinite": 0,
               "duplicates_by_family": Counter(), "family_counts": Counter(), "columns": {}, "seconds": 0.0}
        out = clean_day(tbl, day, dd, rep)
        rep["rows_kept"] = out.num_rows
        pq.write_table(out, out_dir / f"{day}.parquet", compression="zstd")
        rep["seconds"] = round(time.time() - t0, 1)
        report["days"][day] = rep
        print(f"  {day}: {rep['rows_in']:>9,} in, {rep['rows_kept']:>9,} kept ({rep['seconds']} s)")
    tot = lambda k: sum(d[k] for d in report["days"].values())  # noqa: E731
    report["totals"] = {k: tot(k) for k in ("rows_in", "rows_kept", "duplicates_removed", "rows_with_nonfinite")}
    (out_dir / "clean_report.json").write_text(json.dumps(report, indent=1, default=dict) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw", type=Path, default=RAW)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--max-days", type=int)
    a = ap.parse_args()
    print(json.dumps(process(a.raw, a.out, a.max_days)["totals"], indent=1))
