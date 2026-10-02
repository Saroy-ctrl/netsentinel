"""M2-01 ★: tiny but REAL bundles built from synthetic data, so M3 can run the API before real models exist.

    python scripts/make_mock_bundle.py                      # artifacts/bundles/mock-cic and mock-luflow
    python scripts/make_mock_bundle.py --out some/dir

Same packager and loader as the real bundles (hash-verified, spec-driven), trained on a few thousand random rows
shaped like the real feature specs. The models are meaningless; the plumbing is real. Mock bundles are labelled
(`mock: true` tag, dataset "MOCK (synthetic)") so they can never be mistaken for a trained model.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from nscore.bundle.packager import build_bundle
from nscore.contracts.schemas import AttackFamily
from nscore.drift.psi import build_reference
from nscore.features.transform import FeatureSpec, FlowTransformer

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "nscore" / "contracts"
SCHEMAS = {
    "cic": {"spec": "feature_spec.json", "baseline": "baselines/cic.json", "families": True},
    "luflow": {"spec": "feature_spec.luflow.json", "baseline": "baselines/luflow.json", "families": False},
}
N = 4000


def synthetic_frame(spec: FeatureSpec, rng: np.random.Generator) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    """Features drawn per-spec (lognormal inside each feature's clip range); attacks are shifted so models can learn."""
    cols = {}
    family = rng.choice(["BENIGN", "DoS", "DDoS", "Botnet"], size=N, p=[0.7, 0.1, 0.1, 0.1])
    y = (family != "BENIGN").astype(int)
    for j, f in enumerate(spec.features):
        lo, hi = f.clip
        top = max(hi, lo + 1.0)
        v = np.clip(rng.lognormal(mean=np.log1p(top) / 4, sigma=1.0, size=N), lo, top)
        shift = 1.0 + 0.8 * (j % 5 == 0) * y + 0.3 * (family == "DoS") * (j % 3 == 0)
        cols[f.name] = np.clip(v * shift, lo, top)
    return pd.DataFrame(cols), y, family


def build(schema: str, out_root: Path, seed: int = 0) -> Path:
    cfg = SCHEMAS[schema]
    rng = np.random.default_rng(seed)
    spec_path = CONTRACTS / cfg["spec"]
    spec = FeatureSpec.load(spec_path)
    df, y, family = synthetic_frame(spec, rng)
    tr = FlowTransformer(spec).fit(df)
    X = tr.transform(df)

    rf = RandomForestClassifier(n_estimators=40, max_depth=10, class_weight="balanced_subsample", n_jobs=-1,
                                random_state=seed).fit(X, y)
    multi = None
    if cfg["families"]:
        atk = y == 1
        multi = RandomForestClassifier(n_estimators=40, max_depth=10, random_state=seed).fit(X[atk], family[atk])
        assert all(c in {f.value for f in AttackFamily} for c in multi.classes_)
    iso = IsolationForest(n_estimators=100, max_samples=256, random_state=seed, n_jobs=-1).fit(X[y == 0])
    benign_scores = -iso.score_samples(X[y == 0])

    baseline = json.loads((CONTRACTS / cfg["baseline"]).read_text(encoding="utf-8"))
    report = json.loads((CONTRACTS / "fixtures" / "evaluation_report.json").read_text(encoding="utf-8"))
    report["limitations"] = ["MOCK BUNDLE: synthetic data, meaningless metrics"]
    out = out_root / f"mock-{schema}"
    build_bundle(
        out, version=f"mock-{schema}-0", spec_path=spec_path, transformer=tr, rf_binary=rf, iforest=iso,
        rf_multiclass=multi, benign_val_scores=benign_scores,
        thresholds={"tau_binary": 0.5, "tau_anomaly": 99.0, "operating_fpr": 0.01},
        drift_reference=build_reference(X, tr.feature_names), baseline_stats=baseline,
        dataset="MOCK (synthetic)", split_strategy="none (synthetic)", metrics_summary={"mock": 1.0},
        evaluation_report=report, tags={"mock": "true"}, overwrite=True)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "bundles")
    a = ap.parse_args()
    for s in SCHEMAS:
        print("wrote", build(s, a.out))
