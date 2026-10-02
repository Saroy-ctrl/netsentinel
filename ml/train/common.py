"""Shared helpers for the M2 training scripts (loading, transformer, timing). Not imported by api/."""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from pathlib import Path

import numpy as np
import pandas as pd

from ml.data.working_set import load
from nscore.features.transform import FeatureSpec, FlowTransformer

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "nscore" / "contracts"
EXPERIMENTS = ROOT / "artifacts" / "experiments"
SPECS = {"cic": CONTRACTS / "feature_spec.json", "luflow": CONTRACTS / "feature_spec.luflow.json"}
SEED = 0


@contextmanager
def timed(label: str):
    t = time.perf_counter()
    yield
    print(f"[{label}] {time.perf_counter() - t:.1f}s", flush=True)


def load_split(schema: str, split: str) -> pd.DataFrame:
    return load(schema, split)


def is_attack(df: pd.DataFrame, schema: str) -> np.ndarray:
    """Binary supervised label. LUFlow `Outlier` is NOT a class (excluded by callers), only BENIGN vs Malicious."""
    return (df["family"] != "BENIGN").to_numpy()


def fit_transformer(schema: str, train: pd.DataFrame, include_optional: tuple[str, ...] = ()) -> FlowTransformer:
    return FlowTransformer(FeatureSpec.load(SPECS[schema]), include_optional=include_optional).fit(train)


def out_dir(name: str) -> Path:
    p = EXPERIMENTS / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def dump_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=1, default=float) + "\n", encoding="utf-8")
