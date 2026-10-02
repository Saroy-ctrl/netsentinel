"""M1-05: purged time-blocked split + working samples for the cleaned CSE-CIC-IDS2018 parquet.

    python -m ml.data.split            # reads data/processed/cic2018/*.parquet, writes data/splits/

Rule (docs/03_architecture.md #3.2 P1): inside every (day, family, tool) group, order flows by timestamp;
first 70% of the time-ordered flows -> train, next 15% -> val, last 15% -> test. Boundaries are decided by
*timestamp*, so flows with identical timestamps always land on the same side. Flows within `purge` seconds of a
boundary are dropped (split = -1) so one attack session never straddles two sets. purge = min(60 s, 2% of the
group's time span), which keeps short groups from being purged away.

Why per (day, family, tool): each attack lives on one or two days (a day split would drop whole families), and
tools inside a family run at different times (LOIC-UDP vs HOIC), so each must have its own test block.

Outputs in data/splits/:
  cic2018_split.parquet   day, row, split (0 train, 1 val, 2 test, -1 purged), in_sample (bool)
  split_manifest.json     params, counts per split x family/tool, purge counts
`in_sample` marks the working sample: train = up to `cap_per_tool` flows per attack tool + `benign_train` benign;
val/test = every attack flow + `benign_eval` random benign flows (unbiased for FPR). Fixed seed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[2]
PROCESSED = ROOT / "data" / "processed" / "cic2018"
OUT = ROOT / "data" / "splits"

TRAIN, VAL, TEST, PURGED = 0, 1, 2, -1
FRACS = (0.70, 0.15, 0.15)
PURGE_S = 60.0
PURGE_MAX_SPAN_FRAC = 0.02
SEED = 42
CAP_PER_TOOL = 300_000
BENIGN_TRAIN = 2_500_000
BENIGN_EVAL = 1_500_000


def _assign_group(ts: np.ndarray) -> np.ndarray:
    """ts: int64 microseconds. Returns int8 split ids for one group."""
    n = len(ts)
    out = np.full(n, PURGED, dtype=np.int8)
    if n == 0:
        return out
    srt = np.sort(ts)
    t1, t2 = srt[min(int(n * FRACS[0]), n - 1)], srt[min(int(n * (FRACS[0] + FRACS[1])), n - 1)]
    span = float(srt[-1] - srt[0])
    purge = int(min(PURGE_S * 1e6, PURGE_MAX_SPAN_FRAC * span))
    out[ts < t1 - purge] = TRAIN
    out[(ts >= t1 + purge) & (ts < t2 - purge)] = VAL
    out[ts >= t2 + purge] = TEST
    return out


def assign_splits(meta: pd.DataFrame) -> np.ndarray:
    """meta needs: day, ts (datetime64[us]), family, tool. Groups never cross days."""
    split = np.full(len(meta), PURGED, dtype=np.int8)
    ts = meta["ts"].to_numpy().astype("datetime64[us]").astype("int64")
    for _, idx in meta.groupby(["day", "family", "tool"], observed=True, sort=False).indices.items():
        split[idx] = _assign_group(ts[idx])
    return split


def working_sample(meta: pd.DataFrame, split: np.ndarray, seed: int = SEED, cap_per_tool: int = CAP_PER_TOOL,
                   benign_train: int = BENIGN_TRAIN, benign_eval: int = BENIGN_EVAL) -> np.ndarray:
    rng = np.random.default_rng(seed)
    attack = (meta["family"] != "BENIGN").to_numpy()
    sel = np.zeros(len(meta), dtype=bool)
    tool = meta["tool"].astype(str).to_numpy()
    for s in (TRAIN, VAL, TEST):
        in_split = split == s
        a_idx = np.flatnonzero(in_split & attack)
        if s == TRAIN:  # cap each attack tool, random within the tool
            for t in np.unique(tool[a_idx]):
                ti = a_idx[tool[a_idx] == t]
                sel[rng.choice(ti, size=min(len(ti), cap_per_tool), replace=False)] = True
        else:
            sel[a_idx] = True
        b_idx = np.flatnonzero(in_split & ~attack)
        want = benign_train if s == TRAIN else benign_eval
        sel[rng.choice(b_idx, size=min(len(b_idx), want), replace=False)] = True
    return sel


def exclude_family(meta: pd.DataFrame, split: np.ndarray, family: str) -> np.ndarray:
    """LOAO fold: train/val mask with one family removed. The held-out family is still scored in `test`."""
    return (np.isin(split, (TRAIN, VAL))) & (meta["family"].to_numpy() != family)


def exclude_tool(meta: pd.DataFrame, split: np.ndarray, tool: str) -> np.ndarray:
    """Tool-holdout fold (e.g. DDoS-HOIC): LOIC stays in train, HOIC is only ever scored."""
    return (np.isin(split, (TRAIN, VAL))) & (meta["tool"].astype(str).to_numpy() != tool)


def load_meta(processed: Path = PROCESSED) -> pd.DataFrame:
    parts = []
    for f in sorted(processed.glob("*.parquet")):
        t = pq.read_table(f, columns=["day", "row", "ts", "family", "tool"])
        df = t.to_pandas()
        for c in ("day", "family", "tool"):
            df[c] = df[c].astype("category")
        parts.append(df)
    return pd.concat(parts, ignore_index=True)


def build_manifest(meta: pd.DataFrame, split: np.ndarray, sample: np.ndarray) -> dict:
    names = {TRAIN: "train", VAL: "val", TEST: "test", PURGED: "purged"}
    cols = list(names.values())
    key = (meta["family"].astype(str) + " / " + meta["tool"].astype(str)).to_numpy()
    counts = pd.crosstab(pd.Series(key), pd.Series(split).map(names)).reindex(columns=cols, fill_value=0)
    # NB: both Series must be plain-positional (same RangeIndex) or crosstab aligns on stale labels
    in_sample = pd.crosstab(pd.Series(key[sample]), pd.Series(split[sample]).map(names)).reindex(
        columns=cols[:3], fill_value=0)
    return {
        "params": {"fracs": FRACS, "purge_s": PURGE_S, "purge_max_span_frac": PURGE_MAX_SPAN_FRAC, "seed": SEED,
                   "cap_per_tool": CAP_PER_TOOL, "benign_train": BENIGN_TRAIN, "benign_eval": BENIGN_EVAL},
        "totals": {names[s]: int((split == s).sum()) for s in (TRAIN, VAL, TEST, PURGED)},
        "sample_totals": {names[s]: int(((split == s) & sample).sum()) for s in (TRAIN, VAL, TEST)},
        "counts": counts.to_dict(orient="index"),
        "sample_counts": in_sample.to_dict(orient="index"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--processed", type=Path, default=PROCESSED)
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args()
    meta = load_meta(a.processed)
    print(f"{len(meta):,} flows")
    split = assign_splits(meta)
    sample = working_sample(meta, split)

    a.out.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table({"day": meta["day"].astype(str).to_numpy(), "row": meta["row"].to_numpy(),
                             "split": split, "in_sample": sample}),
                   a.out / "cic2018_split.parquet", compression="zstd")

    manifest = build_manifest(meta, split, sample)
    (a.out / "split_manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    print(pd.DataFrame(manifest["counts"]).T.to_string())
    print("\nworking sample:", manifest["sample_totals"])


if __name__ == "__main__":
    main()
