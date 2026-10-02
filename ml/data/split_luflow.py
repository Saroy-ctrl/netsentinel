"""M1-09: temporal split for the cleaned LUFlow parquet (real-traffic drift study, P3 / P3b in docs/03 #3.2).

    python -m ml.data.split_luflow

Early months (EARLY_PERIODS, default 2020-06 and 2020-07) are split like 2018: per (month, label) groups ordered
by time, 70/15/15 -> train / val / test (the "same period" baseline), purged at the boundaries.
Every later month is a pure drift test set:
    split 3 "recal": benign flows from the FIRST 20% of that month's time span (minus a 60 s purge). This is the
                     "recent known-good traffic" a SOC could collect without labelling attacks (LUFlow's `benign`
                     = known production services); used to refit only the IsolationForest + thresholds (P3b).
    split 2 "test" : every flow after that 20% mark (plus a 60 s purge), all three labels.
`outlier` flows keep their split but are never in the supervised train sample (they are the novelty showcase).

Outputs data/splits/luflow_split.parquet (period, day, row, split, in_sample) + luflow_split_manifest.json.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from ml.data.split import PURGE_S, PURGED, TEST, TRAIN, VAL, assign_splits

ROOT = Path(__file__).resolve().parents[2]
PROCESSED = ROOT / "data" / "processed" / "luflow"
OUT = ROOT / "data" / "splits"

RECAL = 3
EARLY_PERIODS = ("2020-06", "2020-07")
RECAL_FRAC = 0.20
SEED = 42
TRAIN_PER_LABEL = 1_500_000
EVAL_PER_LABEL = 400_000
EVAL_OUTLIER = 200_000
LATER_TEST_SAMPLE = 1_000_000
RECAL_SAMPLE = 500_000


def assign_luflow(meta: pd.DataFrame, early: tuple[str, ...] = EARLY_PERIODS) -> np.ndarray:
    """meta needs: period, ts (datetime64[us]), family, tool (= raw label)."""
    split = np.full(len(meta), PURGED, dtype=np.int8)
    is_early = meta["period"].isin(early).to_numpy()
    if is_early.any():
        e = meta[is_early].drop(columns=["day"]).rename(columns={"period": "day"})  # group by month, not file
        split[np.flatnonzero(is_early)] = assign_splits(e)
    ts = meta["ts"].to_numpy().astype("datetime64[us]").astype("int64")
    benign = (meta["family"] == "BENIGN").to_numpy()
    for idx in meta[~is_early].groupby("period", observed=True).indices.values():
        pos = np.flatnonzero(~is_early)[idx]
        t = ts[pos]
        boundary = t.min() + RECAL_FRAC * (t.max() - t.min())
        purge = PURGE_S * 1e6
        split[pos[t >= boundary + purge]] = TEST
        split[pos[(t < boundary - purge) & benign[pos]]] = RECAL
    return split


def working_sample(meta: pd.DataFrame, split: np.ndarray, early: tuple[str, ...] = EARLY_PERIODS,
                   seed: int = SEED) -> np.ndarray:
    rng = np.random.default_rng(seed)
    sel = np.zeros(len(meta), dtype=bool)
    fam = meta["family"].astype(str).to_numpy()
    per = meta["period"].astype(str).to_numpy()
    is_early = np.isin(per, early)

    def pick(mask: np.ndarray, n: int) -> None:
        idx = np.flatnonzero(mask)
        sel[rng.choice(idx, size=min(len(idx), n), replace=False)] = True

    for label in ("BENIGN", "Malicious"):
        pick((split == TRAIN) & (fam == label), TRAIN_PER_LABEL)
        for s in (VAL, TEST):
            pick(is_early & (split == s) & (fam == label), EVAL_PER_LABEL)
    for s in (VAL, TEST):
        pick(is_early & (split == s) & (fam == "Outlier"), EVAL_OUTLIER)
    for period in sorted(set(per[~is_early])):
        in_p = per == period
        pick(in_p & (split == TEST), LATER_TEST_SAMPLE)
        pick(in_p & (split == RECAL), RECAL_SAMPLE)
    return sel


def load_meta(processed: Path = PROCESSED) -> pd.DataFrame:
    parts = []
    for f in sorted(processed.glob("*.parquet")):
        df = pq.read_table(f, columns=["period", "day", "row", "ts", "family", "tool"]).to_pandas()
        for c in ("period", "day", "family", "tool"):
            df[c] = df[c].astype("category")
        parts.append(df)
    return pd.concat(parts, ignore_index=True)


def build_manifest(meta: pd.DataFrame, split: np.ndarray, sample: np.ndarray) -> dict:
    names = {TRAIN: "train", VAL: "val", TEST: "test", RECAL: "recal", PURGED: "purged"}
    cols = list(names.values())
    key = (meta["period"].astype(str) + " / " + meta["family"].astype(str)).to_numpy()
    counts = pd.crosstab(pd.Series(key), pd.Series(split).map(names)).reindex(columns=cols, fill_value=0)
    scounts = pd.crosstab(pd.Series(key[sample]), pd.Series(split[sample]).map(names)).reindex(
        columns=cols[:4], fill_value=0)
    return {
        "params": {"early_periods": EARLY_PERIODS, "recal_frac": RECAL_FRAC, "purge_s": PURGE_S, "seed": SEED,
                   "train_per_label": TRAIN_PER_LABEL, "eval_per_label": EVAL_PER_LABEL,
                   "later_test_sample": LATER_TEST_SAMPLE, "recal_sample": RECAL_SAMPLE},
        "totals": {n: int((split == s).sum()) for s, n in names.items()},
        "sample_totals": {names[s]: int(((split == s) & sample).sum()) for s in (TRAIN, VAL, TEST, RECAL)},
        "counts": counts.to_dict(orient="index"), "sample_counts": scounts.to_dict(orient="index"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--processed", type=Path, default=PROCESSED)
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args()
    meta = load_meta(a.processed)
    print(f"{len(meta):,} flows, periods {sorted(meta['period'].unique())}")
    split = assign_luflow(meta)
    sample = working_sample(meta, split)
    a.out.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table({"period": meta["period"].astype(str).to_numpy(), "day": meta["day"].astype(str).to_numpy(),
                             "row": meta["row"].to_numpy(), "split": split, "in_sample": sample}),
                   a.out / "luflow_split.parquet", compression="zstd")
    manifest = build_manifest(meta, split, sample)
    (a.out / "luflow_split_manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    print(pd.DataFrame(manifest["counts"]).T.to_string())
    print("\nworking sample:", int(sample.sum()))


if __name__ == "__main__":
    main()
