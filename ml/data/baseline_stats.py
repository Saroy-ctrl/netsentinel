"""M1-08: benign-traffic statistics per feature -> baseline_stats.json (goes into every model bundle).

    python -m ml.data.baseline_stats cic       # from the 2018 train sample, writes data/processed/cic2018/
    python -m ml.data.baseline_stats luflow

Powers the "vs normal" line on every alert ("this flow's inter-arrival time is 4,000x shorter than normal") and
the FeatureContribution.baseline_median field. RAW values (not clipped, not log1p'd), BENIGN flows of the TRAIN
sample only, features exactly as listed in the schema's feature spec (+ optional ones, flagged).

JSON: {"schema": "cic", "n_benign": N, "features": {name: {"median", "p05", "p95", "mean", "std", "zero_share"}}}
`ratio_to_median(value, stats)` is the shared helper the API and the brief generator use for the wording.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]


def compute(benign: pd.DataFrame, names: list[str]) -> dict:
    out = {}
    for n in names:
        v = benign[n].to_numpy(dtype=np.float64)
        v = v[np.isfinite(v)]
        out[n] = {
            "median": float(np.median(v)), "p05": float(np.quantile(v, 0.05)), "p95": float(np.quantile(v, 0.95)),
            "mean": float(v.mean()), "std": float(v.std()), "zero_share": float((v == 0).mean()),
        }
    return out


def ratio_to_median(value: float, stats: dict, floor: float = 1e-9) -> float | None:
    """value / benign median, or None when the median is ~0 (a ratio would be meaningless; compare to p95 instead)."""
    m = stats["median"]
    return None if abs(m) < floor else float(value / m)


def _x(factor: float) -> str:
    return f"{factor:,.0f}x" if factor >= 10 else f"{factor:.1f}x"


def describe(name: str, value: float, stats: dict) -> str:
    """One human sentence for an alert: used by the template brief and as a hint for the LLM prompt."""
    label = name.replace("_", " ")
    r = ratio_to_median(value, stats)
    if r is None:
        if value > stats["p95"]:
            return f"{label} is {value:,.4g}, above the benign 95th percentile ({stats['p95']:,.4g})"
        return f"{label} is {value:,.4g} (benign traffic is usually 0)"
    if r >= 2:
        return f"{label} is {_x(r)} the benign median"
    if 0 < r <= 0.5:
        return f"{label} is {_x(1 / r)} below the benign median"
    return f"{label} is close to the benign median"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("schema", choices=["cic", "luflow"])
    a = ap.parse_args()
    if a.schema == "cic":
        from ml.data import make_feature_spec as m
        label_col = "tool"
    else:
        from ml.data import make_feature_spec_luflow as m
        label_col = "family"
    sample, benign_value, out_dir = m.build_sample(m.PROCESSED, m.SPLITS), "BENIGN", m.PROCESSED
    spec = json.loads(Path(m.SPEC_PATH).read_text(encoding="utf-8"))
    names = [f["name"] for f in spec["features"]]
    if label_col not in sample:
        raise SystemExit(f"sample has no {label_col!r} column")
    benign = sample[sample[label_col].astype(str) == benign_value].copy()
    benign["protocol"] = benign["protocol"].astype("float32")
    stats = compute(benign, names)
    out = {"schema": a.schema, "n_benign": int(len(benign)), "features": stats}
    path = Path(out_dir) / "baseline_stats.json"
    path.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(f"{len(benign):,} benign flows, {len(names)} features -> {path}")


if __name__ == "__main__":
    main()
