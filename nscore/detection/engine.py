"""Detection engine (M2): a loaded bundle + flows -> verdicts. The ONE implementation used by evaluation (ml/) and the
API (api/), so offline metrics and live behaviour cannot drift apart.

    eng = DetectionEngine(bundle)
    det = eng.detect(df_or_records)          # vectorised; no SHAP here (explanations: nscore.detection.explain)

Per flow:   p  = rf_binary P(attack)
            a  = IsolationForest anomaly percentile among BENIGN validation flows (0-100, 100 = most anomalous)
            v  = fuse(p, a, tau_binary, tau_anomaly)               KNOWN_ATTACK | NOVEL_ANOMALY | BENIGN
KNOWN_ATTACK -> family from rf_multiclass (+ probabilities, used for expected severity); binary-only bundles
(LUFlow) answer `Malicious`. NOVEL_ANOMALY -> family `Unknown`. `confidence` is what the risk engine multiplies:
p for known attacks, novel_confidence(a) for novel anomalies.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from nscore.contracts.schemas import AttackFamily, Verdict
from nscore.detection.fusion import fuse, novel_confidence


@dataclass
class Detections:
    verdict: list[Verdict]
    p_attack: np.ndarray
    anomaly_percentile: np.ndarray
    family: list[AttackFamily]
    family_confidence: np.ndarray  # NaN where there is no family decision
    family_probs: list[dict[AttackFamily, float] | None]
    confidence: np.ndarray  # risk-engine confidence (0 for benign)
    X: np.ndarray  # the transformed matrix actually scored (for SHAP / drift / debugging)

    def __len__(self) -> int:
        return len(self.verdict)


class DetectionEngine:
    def __init__(self, bundle) -> None:
        self.bundle = bundle
        self.tau_binary = float(bundle.thresholds["tau_binary"])
        self.tau_anomaly = float(bundle.thresholds["tau_anomaly"])
        self._sorted_scores = np.sort(np.asarray(bundle.benign_val_scores, dtype=np.float64))

    # --------------------------------------------------------------- scoring pieces (also used by evaluation)
    def transform(self, flows) -> np.ndarray:
        tr = self.bundle.transformer
        if isinstance(flows, pd.DataFrame):
            return tr.transform(flows)
        if isinstance(flows, np.ndarray):
            return flows.astype(np.float32, copy=False)
        return tr.transform_records(list(flows))

    def p_attack(self, X: np.ndarray) -> np.ndarray:
        proba = self.bundle.rf_binary.predict_proba(X)
        classes = list(self.bundle.rf_binary.classes_)
        return proba[:, classes.index(1)] if 1 in classes else np.zeros(len(X))

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Higher = more anomalous (negated IsolationForest score_samples)."""
        return -self.bundle.iforest.score_samples(X)

    def anomaly_percentile(self, X: np.ndarray) -> np.ndarray:
        s = self.anomaly_score(X)
        return 100.0 * np.searchsorted(self._sorted_scores, s, side="right") / len(self._sorted_scores)

    # --------------------------------------------------------------- full decision
    def decide(self, p: np.ndarray, pct: np.ndarray) -> list[Verdict]:
        return [fuse(float(a), float(b), self.tau_binary, self.tau_anomaly) for a, b in zip(p, pct, strict=True)]

    def detect(self, flows) -> Detections:
        X = self.transform(flows)
        p, pct = self.p_attack(X), self.anomaly_percentile(X)
        verdict = self.decide(p, pct)
        n = len(X)
        family = [AttackFamily.BENIGN] * n
        fconf = np.full(n, np.nan)
        fprobs: list[dict[AttackFamily, float] | None] = [None] * n
        conf = np.zeros(n)

        known = np.array([v is Verdict.KNOWN_ATTACK for v in verdict], dtype=bool)
        novel = np.array([v is Verdict.NOVEL_ANOMALY for v in verdict], dtype=bool)
        if known.any():
            conf[known] = p[known]
            multi = self.bundle.rf_multiclass
            if multi is None:  # binary-only bundle
                for i in np.flatnonzero(known):
                    family[i] = AttackFamily.MALICIOUS
            else:
                proba = multi.predict_proba(X[known])
                classes = [AttackFamily(str(c)) for c in multi.classes_]
                for row, i in zip(proba, np.flatnonzero(known), strict=True):
                    probs = {c: float(q) for c, q in zip(classes, row, strict=True)}
                    best = max(probs, key=probs.get)
                    family[i], fconf[i], fprobs[i] = best, probs[best], probs
        for i in np.flatnonzero(novel):
            family[i] = AttackFamily.UNKNOWN
            conf[i] = novel_confidence(float(pct[i]), self.tau_anomaly)
        return Detections(verdict, p, pct, family, fconf, fprobs, conf, X)
