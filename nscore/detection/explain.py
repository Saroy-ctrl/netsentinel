"""Per-alert explanations (M2-09): SHAP for the binary RandomForest, joined with benign baselines.

    ex = Explainer(bundle)
    top = ex.contributions(det.X, det.raw, k=5)          # list (one per row) of FeatureContribution (contract)

Each contribution carries the RAW feature value (human readable, not clipped/log'd), its SHAP value for the
"attack" class (positive = pushed towards attack), and the benign median from the bundle's baseline_stats, so the UI
and brief can say "flow IAT mean is 4,000x below the benign median" (ml.data.baseline_stats.describe).

Cost: exact TreeSHAP is ~50-110 ms per flow on this forest. Callers must not explain every flow of an alert
storm: explain a few representative flows per incident (fast=True uses the first `fast_trees` trees, ~4x quicker).
The explainer is rebuilt from the model at load (cheap) instead of being pickled: pickled explainers break across shap
versions.
"""

from __future__ import annotations

import copy

import numpy as np

from nscore.contracts.schemas import FeatureContribution


class Explainer:
    def __init__(self, bundle, fast_trees: int = 25) -> None:
        import shap  # lazy: only the API process that explains needs it

        self.names: list[str] = bundle.transformer.feature_names
        self.baseline = bundle.baseline_stats.get("features", {})
        rf = bundle.rf_binary
        self._attack_idx = list(rf.classes_).index(1)
        self._full = shap.TreeExplainer(rf)
        small = copy.copy(rf)
        small.estimators_ = rf.estimators_[:fast_trees]
        small.n_estimators = len(small.estimators_)
        self._fast = shap.TreeExplainer(small)

    def shap_values(self, X: np.ndarray, fast: bool = False) -> np.ndarray:
        """(n, n_features) SHAP values for the attack class."""
        sv = (self._fast if fast else self._full).shap_values(np.asarray(X, dtype=np.float32), check_additivity=False)
        sv = np.asarray(sv)
        if sv.ndim == 3:  # (n, features, classes) in shap >= 0.45
            return sv[:, :, self._attack_idx]
        return sv  # already (n, features)

    def contributions(self, X: np.ndarray, raw: np.ndarray, k: int = 5, fast: bool = False
                      ) -> list[list[FeatureContribution]]:
        sv = self.shap_values(X, fast=fast)
        out = []
        for i in range(len(sv)):
            top = np.argsort(-np.abs(sv[i]))[:k]
            out.append([
                FeatureContribution(
                    feature=self.names[j], value=float(raw[i, j]), shap_value=float(sv[i, j]),
                    baseline_median=self.baseline.get(self.names[j], {}).get("median"))
                for j in top
            ])
        return out

    def global_importance(self, X_sample: np.ndarray, fast: bool = True) -> list[tuple[str, float]]:
        """Mean |SHAP| per feature over a sample, for the Model page ("what does the model generally look at")."""
        m = np.abs(self.shap_values(X_sample, fast=fast)).mean(axis=0)
        return sorted(zip(self.names, map(float, m), strict=True), key=lambda kv: -kv[1])
