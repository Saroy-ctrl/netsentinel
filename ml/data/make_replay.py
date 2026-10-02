"""M1-10: replay extracts for M5's replay engine: time-ordered slices of the held-out TEST split, with ground truth.

    python -m ml.data.make_replay              # writes replay/samples/*.csv.gz + manifest.json

Every file is one scenario, <= 10,000 flows, sorted by time, columns:
    flow_id, observed_at (UTC), t_rel_s (seconds since the first flow, for pacing), src_ip, src_port, dst_ip,
    dst_port, protocol, ground_truth (family / label), tool (raw dataset label), then one column per feature of
    the schema's feature spec (snake_case names = what POST /v1/flows expects in FlowRecord.features).
    `protocol` appears once and is both FlowMeta.protocol and the `protocol` feature.
    Ports: LUFlow's -1 ("protocol has no ports") is written as 0 because FlowMeta requires 0..65535; ports are
    display-only metadata (the incident key is src_ip, dst_ip, family).
Non-finite feature values (57 flows in all of 2018) are replaced by the spec's train median, the same rule the
FlowTransformer applies, because JSON cannot carry NaN. Counts are in manifest.json.

2018 files use the CIC schema; luflow_* files need the LUFlow bundle. Attack files are contiguous test-block
slices (a real burst), benign background is a contiguous window of a normal day; M5 mixes them in scenarios/*.yaml.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ml.data.split import OUT as SPLITS
from ml.data.split import PROCESSED as CIC_PROCESSED
from ml.data.split import TEST
from ml.data.split_luflow import PROCESSED as LU_PROCESSED

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "replay" / "samples"
N = 10_000
SEED = 11
META = ["ts", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "family", "tool"]

# name -> list of (day file stem, raw tool label). Contiguous slice of the test block, starting mid-block.
CIC_SCENARIOS = {
    "2018_benign_background": [("Wednesday-14-02-2018", "BENIGN")],
    "2018_ssh_bruteforce": [("Wednesday-14-02-2018", "SSH-BruteForce")],
    "2018_dos_hulk": [("Friday-16-02-2018", "DoS Hulk")],
    "2018_ddos_hoic": [("Wednesday-21-02-2018", "DDoS-HOIC")],
    "2018_botnet_ares": [("Friday-02-03-2018", "Botnet Ares")],
    "2018_infiltration_nmap": [("Wednesday-28-02-2018", "Infiltration - NMAP Portscan")],
    "2018_webattack_all": [("Thursday-22-02-2018", t) for t in
                           ("Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL")]
                          + [("Friday-23-02-2018", t) for t in
                             ("Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL")],
}
LUFLOW_PERIODS = ["2020-06", "2020-08", "2020-10", "2020-12", "2021-02"]  # 2020-06 = same-period baseline


def _split_rows(split_path: Path, key: str, value: str) -> pd.DataFrame:
    return pq.read_table(split_path, filters=[(key, "=", value)], columns=["day", "row", "split"]).to_pandas()


def _load(processed: Path, day: str, tools: list[str], rows_test: np.ndarray, feats: list[str],
          by: str = "tool") -> pd.DataFrame:
    cols = list(dict.fromkeys(["row", *META, *feats]))  # `protocol` is both metadata and a feature
    df = pq.read_table(processed / f"{day}.parquet", columns=cols, filters=[(by, "in", tools)]).to_pandas()
    df = df[np.isin(df["row"].to_numpy(), rows_test)].copy()
    df["day"] = day
    return df


def _finish(df: pd.DataFrame, feats: list[str], medians: dict[str, float], name: str, n: int, how: str,
            rng: np.random.Generator) -> tuple[pd.DataFrame, dict]:
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    total = len(df)
    if how == "middle" and total > n:
        start = (total - n) // 2
        df = df.iloc[start:start + n]
    elif total > n:  # random, then re-sort
        df = df.iloc[np.sort(rng.choice(total, size=n, replace=False))]
    df = df.reset_index(drop=True)
    X = df[feats].astype("float64")
    nonfinite = int((~np.isfinite(X.to_numpy())).sum())
    X = X.mask(~np.isfinite(X), other=pd.Series(medians), axis=1) if nonfinite else X
    out = pd.DataFrame({
        "flow_id": df["day"] + "-" + df["row"].astype(str),
        "observed_at": df["ts"].dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "t_rel_s": ((df["ts"] - df["ts"].iloc[0]).dt.total_seconds()).round(6),
        "src_ip": df["src_ip"], "src_port": df["src_port"].clip(lower=0), "dst_ip": df["dst_ip"],
        "dst_port": df["dst_port"].clip(lower=0),
        "protocol": df["protocol"], "ground_truth": df["family"].astype(str), "tool": df["tool"].astype(str),
    })
    # `protocol` is already in `out` (one column feeds both FlowMeta.protocol and features["protocol"])
    out = pd.concat([out, X.drop(columns=["protocol"], errors="ignore").astype("float32")], axis=1)
    info = {"rows": len(out), "available_in_test": total, "nonfinite_replaced": nonfinite,
            "span_s": round(float(out["t_rel_s"].iloc[-1]), 1), "first": out["observed_at"].iloc[0],
            "ground_truth": out["ground_truth"].value_counts().to_dict(),
            "tools": out["tool"].value_counts().to_dict(), "selection": how, "name": name}
    return out, info


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--only", choices=["cic", "luflow"], help="regenerate just one schema (manifest is merged)")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(SEED)
    mpath = a.out / "manifest.json"
    manifest: dict = json.loads(mpath.read_text(encoding="utf-8")) if a.only and mpath.exists() else {"files": {}}
    manifest |= {"n_max": N, "seed": SEED}

    cic_spec = json.loads((ROOT / "nscore" / "contracts" / "feature_spec.json").read_text(encoding="utf-8"))
    feats = [f["name"] for f in cic_spec["features"]]
    medians = {f["name"]: f["train_median"] for f in cic_spec["features"]}
    sp = SPLITS / "cic2018_split.parquet"
    for name, parts in (CIC_SCENARIOS.items() if a.only != "luflow" else []):
        frames = []
        for day in sorted({d for d, _ in parts}):
            tools = [t for d, t in parts if d == day]
            s = _split_rows(sp, "day", day)
            frames.append(_load(CIC_PROCESSED, day, tools, s["row"][s["split"] == TEST].to_numpy(), feats))
        out, info = _finish(pd.concat(frames, ignore_index=True), feats, medians, name, N, "middle", rng)
        out.to_csv(a.out / f"{name}.csv.gz", index=False, float_format="%.8g")
        manifest["files"][name] = info | {"schema": "cic"}
        print(f"{name:28s} {info['rows']:>6,} rows  ({info['available_in_test']:,} in test)  span {info['span_s']} s")

    lu_spec = json.loads((ROOT / "nscore" / "contracts" / "feature_spec.luflow.json").read_text(encoding="utf-8"))
    lfeats = [f["name"] for f in lu_spec["features"]]
    lmed = {f["name"]: f["train_median"] for f in lu_spec["features"]}
    lsp = SPLITS / "luflow_split.parquet"
    for period in (LUFLOW_PERIODS if a.only != "cic" else []):
        s = pq.read_table(lsp, filters=[("period", "=", period)], columns=["day", "row", "split"]).to_pandas()
        frames = []
        for day, g in s[s["split"] == TEST].groupby("day"):
            frames.append(_load(LU_PROCESSED, day, ["benign", "malicious", "outlier"], g["row"].to_numpy(), lfeats))
        out, info = _finish(pd.concat(frames, ignore_index=True), lfeats, lmed, f"luflow_{period}", N, "random", rng)
        out.to_csv(a.out / f"luflow_{period}.csv.gz", index=False, float_format="%.8g")
        manifest["files"][f"luflow_{period}"] = info | {"schema": "luflow"}
        print(f"luflow_{period:26s} {info['rows']:>6,} rows  ({info['available_in_test']:,} in test)  "
              f"{info['ground_truth']}")
    (a.out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
