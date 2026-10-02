"""M1-02: derive nscore/contracts/feature_spec.json from the TRAIN split of cleaned CSE-CIC-IDS2018.

    python -m ml.data.make_feature_spec

Reads data/processed/cic2018/*.parquet + data/splits/cic2018_split.parquet, takes a stratified sample of the
*train* block only (~400k benign + up to 40k flows per attack tool), and hands it to spec_builder.
Also writes data/processed/cic2018/feature_stats.csv and corr_pairs.csv (inputs for docs/data_profile.md).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ml.data import spec_builder as sb
from ml.data.adapters.cic2018 import FEATURE_RAW, FEATURES
from ml.data.split import OUT as SPLITS
from ml.data.split import PROCESSED, TRAIN

ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = ROOT / "nscore" / "contracts" / "feature_spec.json"

BENIGN_TARGET = 400_000
TOOL_CAP = 40_000
SEED = 7

# Derived/summary columns lose a correlation tie to the basic measurement they are computed from.
DERIVED = ("subflow_", "average_packet_size", "fwd_segment_size_avg", "bwd_segment_size_avg",
           "packet_length_variance", "down_per_up_ratio")

METADATA = {
    "day": "bookkeeping (source file)", "row": "bookkeeping (row in source file)",
    "ts": "used only for the time split and incident windows; a clock value would memorise the capture schedule",
    "src_ip": "identifier: the model would memorise attacker hosts instead of behaviour",
    "dst_ip": "identifier: the victim is a handful of fixed servers",
    "src_port": "ephemeral client port: noise, no behavioural signal",
    "family": "label", "tool": "label (raw dataset label)", "attempted": "label (Attempted Category != -1)",
}
OPTIONAL = {"dst_port": "B12 experiment: informative but ties the model to the lab's fixed service ports. "
                        "Excluded by default; M2 may run it both ways and document the result."}


def preference(name: str) -> tuple[int, int]:
    order = ["protocol", *FEATURES]
    return (1 if name.startswith(DERIVED) else 0, order.index(name))


def build_sample(processed: Path, splits: Path) -> pd.DataFrame:
    """Per day: read only that day's split rows (parquet filter pushdown), never the whole 45M-row table."""
    man = json.loads((splits / "split_manifest.json").read_text(encoding="utf-8"))
    train_by_tool = {k.split(" / ")[1]: v["train"] for k, v in man["sample_counts"].items()}
    benign_train = train_by_tool["BENIGN"]
    rng = np.random.default_rng(SEED)
    parts = []
    for f in sorted(processed.glob("*.parquet")):
        day = f.stem
        s = pq.read_table(splits / "cic2018_split.parquet", filters=[("day", "=", day)],
                          columns=["row", "split", "in_sample"]).to_pandas()
        take = np.zeros(int(s["row"].max()) + 1, dtype=bool)
        take[s["row"][(s["split"] == TRAIN) & s["in_sample"]].to_numpy()] = True
        u = rng.random(len(take))
        for batch in pq.ParquetFile(f).iter_batches(batch_size=500_000,
                                                    columns=["row", "tool", "protocol", *FEATURES]):
            df = batch.to_pandas()
            rows = df["row"].to_numpy()
            tool = df["tool"].astype(str)
            frac = np.where(tool == "BENIGN", BENIGN_TARGET / benign_train,
                            np.minimum(1.0, TOOL_CAP / tool.map(lambda t: max(train_by_tool.get(t, 1), 1))))
            keep = take[rows] & (u[rows] < frac)
            parts.append(df[keep].drop(columns=["row"]))
        print(f"{day}: sample so far {sum(map(len, parts)):,}", flush=True)
    return pd.concat(parts, ignore_index=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--processed", type=Path, default=PROCESSED)
    ap.add_argument("--splits", type=Path, default=SPLITS)
    a = ap.parse_args()
    df = build_sample(a.processed, a.splits)
    tools = df.pop("tool").astype(str)
    print("sample:", len(df), "rows;", tools.value_counts().to_dict())
    df["protocol"] = df["protocol"].astype("float32")
    raw = dict(zip(FEATURES, FEATURE_RAW, strict=True)) | {"protocol": "Protocol"}
    spec, stats, pairs = sb.build_spec(
        df, raw_names=raw, preference_key=preference, dataset="CSE-CIC-IDS2018 (corrected, Liu/Engelen et al. 2022)",
        schema="cic", metadata=METADATA, optional=OPTIONAL, groups=tools)
    spec["sample"]["tools"] = tools.value_counts().to_dict()
    SPEC_PATH.write_text(json.dumps(spec, indent=1) + "\n", encoding="utf-8", newline="\n")
    stats.to_csv(a.processed / "feature_stats.csv")
    pairs.to_csv(a.processed / "corr_pairs.csv", index=False)
    print(f"kept {len(spec['features'])} of {len(df.columns)} features -> {SPEC_PATH}")
    for d in spec["dropped"]:
        print(f"  drop {d['name']:32s} {d['reason']}")


if __name__ == "__main__":
    main()
