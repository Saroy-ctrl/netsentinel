"""M1-09: derive nscore/contracts/feature_spec.luflow.json from the TRAIN split of cleaned LUFlow.

    python -m ml.data.make_feature_spec_luflow

Sample = train-block flows labelled benign or malicious (150k each, fixed seed). `outlier` is never used for
fitting anything. Same builder, same rules as the 2018 spec; only the column names differ.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ml.data import spec_builder as sb
from ml.data.adapters.luflow import FEATURES, RAW_NAMES
from ml.data.split import TRAIN
from ml.data.split_luflow import OUT as SPLITS
from ml.data.split_luflow import PROCESSED

ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = ROOT / "nscore" / "contracts" / "feature_spec.luflow.json"
PER_LABEL = 150_000
SEED = 7

# total_entropy ~ entropy x bytes, so on a correlation tie it loses to the basic measurement.
ORDER = ["protocol", *FEATURES]
DERIVED = ("total_entropy",)

METADATA = {
    "period": "month, used for the drift study", "day": "bookkeeping (source file)",
    "row": "bookkeeping (row in source file)",
    "ts": "time_start repaired to UTC microseconds; used only for splits and incident windows",
    "src_ip": "identifier: anonymised to the owning network, would memorise sources",
    "dst_ip": "identifier: anonymised to the owning network",
    "src_port": "ephemeral client port: noise", "family": "label (BENIGN / Malicious / Outlier)",
    "tool": "label (raw: benign / malicious / outlier)",
}
OPTIONAL = {"dst_port": "B12 experiment: honeypot services sit on fixed ports, so it flatters the lab-style "
                        "result. Excluded by default; blank ports are stored as -1."}


def preference(name: str) -> tuple[int, int]:
    return (1 if name in DERIVED else 0, ORDER.index(name))


def build_sample(processed: Path, splits: Path) -> pd.DataFrame:
    rng = np.random.default_rng(SEED)
    totals = {"BENIGN": 0, "Malicious": 0}
    meta = json.loads((splits / "luflow_split_manifest.json").read_text(encoding="utf-8"))
    for key, v in meta["sample_counts"].items():
        period, fam = key.split(" / ")
        if fam in totals:
            totals[fam] += v["train"]
    frac = {k: min(1.0, PER_LABEL / max(v, 1)) for k, v in totals.items()}
    parts = []
    for f in sorted(processed.glob("*.parquet")):
        s = pq.read_table(splits / "luflow_split.parquet", filters=[("day", "=", f.stem)],
                          columns=["row", "split", "in_sample"]).to_pandas()
        if s.empty:
            continue
        take = np.zeros(int(s["row"].max()) + 1, dtype=bool)
        take[s["row"][(s["split"] == TRAIN) & s["in_sample"]].to_numpy()] = True
        df = pq.read_table(f, columns=["row", "family", "protocol", *FEATURES]).to_pandas()
        fam = df["family"].astype(str)
        p = fam.map(frac).fillna(0.0).to_numpy()
        keep = take[df["row"].to_numpy()] & (rng.random(len(df)) < p)
        parts.append(df[keep].drop(columns=["row"]))
    return pd.concat(parts, ignore_index=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--processed", type=Path, default=PROCESSED)
    ap.add_argument("--splits", type=Path, default=SPLITS)
    a = ap.parse_args()
    df = build_sample(a.processed, a.splits)
    fam = df.pop("family").astype(str)
    print("sample:", len(df), "rows;", fam.value_counts().to_dict())
    df["protocol"] = df["protocol"].astype("float32")
    spec, stats, pairs = sb.build_spec(
        df, raw_names=RAW_NAMES, preference_key=preference, dataset="LUFlow (Lancaster University honeypots, 2020-21)",
        schema="luflow", metadata=METADATA, optional=OPTIONAL, groups=fam)
    spec["sample"]["labels"] = fam.value_counts().to_dict()
    SPEC_PATH.write_text(json.dumps(spec, indent=1) + "\n", encoding="utf-8", newline="\n")
    stats.to_csv(a.processed / "feature_stats.csv")
    pairs.to_csv(a.processed / "corr_pairs.csv", index=False)
    print(f"kept {len(spec['features'])} of {len(df.columns)} features -> {SPEC_PATH}")
    for d in spec["dropped"]:
        print(f"  drop {d['name']:20s} {d['reason']}")


if __name__ == "__main__":
    main()
