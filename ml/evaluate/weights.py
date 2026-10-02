"""Sampling-weight correction for the stratified val/test samples (see ml/data/split.py working_sample).

Each (family, tool) group (CIC) or (period, family) group (LUFlow) was sampled at some fraction f of its split rows.
A row from that group therefore represents 1/f real rows: weight = full_count / sample_count. Attacks are kept in full
(weight 1); benign is down-sampled (weight ~4), so weighting restores the real class balance.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

SPLITS = Path(__file__).resolve().parents[2] / "data" / "splits"


def _weights(keys: pd.Series, counts: dict, sample_counts: dict, split: str) -> np.ndarray:
    ratio = {}
    for k in counts:
        full, got = counts[k].get(split, 0), sample_counts.get(k, {}).get(split, 0)
        if got:
            ratio[k] = full / got
    w = keys.map(ratio)
    if w.isna().any():
        raise ValueError(f"rows from groups missing in the split manifest: {sorted(keys[w.isna()].unique())[:5]}")
    return w.to_numpy(dtype=np.float64)


def cic_weights(df: pd.DataFrame, split: str, splits_dir: Path = SPLITS) -> np.ndarray:
    man = json.loads((splits_dir / "split_manifest.json").read_text(encoding="utf-8"))
    keys = df["family"].astype(str) + " / " + df["tool"].astype(str)
    return _weights(keys, man["counts"], man["sample_counts"], split)


def luflow_weights(df: pd.DataFrame, split: str, splits_dir: Path = SPLITS) -> np.ndarray:
    man = json.loads((splits_dir / "luflow_split_manifest.json").read_text(encoding="utf-8"))
    keys = df["period"].astype(str) + " / " + df["family"].astype(str)
    return _weights(keys, man["counts"], man["sample_counts"], split)
