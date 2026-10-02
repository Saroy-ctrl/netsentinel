"""Detection engine (M2): a loaded bundle + flows -> verdicts. The ONE implementation used by evaluation (ml/) and the
API (api/), so offline metrics and live behaviour cannot drift apart.

    eng = DetectionEngine(bundle)
    det = eng.detect(df_or_records)          # vectorised; no SHAP here (explanations: nscore.detection.explain)

Per flow:   p  = rf_binary P(attack)
            if p >= tau_binary:  family head -> probabilities; confidence = max prob
                                 confidence < tau_family -> NOVEL_ANOMALY (family UNKNOWN, `closest_family` = argmax)
                                 else KNOWN_ATTACK (family named)
            else:                optional IsolationForest percentile >= tau_anomaly -> NOVEL_ANOMALY, else BENIGN
Binary-only bundles (LUFlow) answer `Malicious` and use the optional anomaly path for novelty. `confidence` is what the
risk engine multiplies: p for flagged attacks, novel_confidence(a) for anomaly-path novelties, 0 for benign.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from nscore.contracts.schemas import AttackFamily, Verdict
from nscore.detection.fusion import ANOMALY_DISABLED, fuse, novel_confidence


@dataclass
class Detections:
    verdict: list[Verdict]
    p_attack: np.ndarray
    anomaly_percentile: np.ndarray  # 0.0 when the bundle has no anomaly detector
    family: list[AttackFamily]  # UNKNOWN for novel anomalies
    closest_family: list[AttackFamily | None]  # argmax of the family head for flagged flows (also for novel ones)
    family_confidence: np.ndarray  # NaN where there is no family decision
    family_probs: list[dict[AttackFamily, float] | None]
    confidence: np.ndarray  # risk-engine confidence (0 for benign)
    X: np.ndarray  # the transformed matrix actually scored (for SHAP / drift / debugging)
    raw: np.ndarray | None = None  # untouched feature values in spec order (explanations show these)

    def __len__(self) -> int:
        return len(self.verdict)


class DetectionEngine:
    def __init__(self, bundle) -> None:
        self.bundle = bundle
        t = bundle.thresholds
        self.tau_binary = float(t["tau_binary"])
        self.tau_family = float(t.get("tau_family", 0.0))
        self.tau_anomaly = float(t.get("tau_anomaly", ANOMALY_DISABLED))
        self.has_anomaly = bundle.iforest is not None
        self._sorted_scores = (np.sort(np.asarray(bundle.benign_val_scores, dtype=np.float64))
                               if self.has_anomaly else None)

    # --------------------------------------------------------------- scoring pieces (also used by evaluation)
    def _frame(self, flows) -> pd.DataFrame | None:
        if isinstance(flows, pd.DataFrame):
            return flows
        if isinstance(flows, np.ndarray):
            return None
        return pd.DataFrame.from_records(list(flows))

    def transform(self, flows) -> np.ndarray:
        frame = self._frame(flows)
        if frame is None:
            return np.asarray(flows).astype(np.float32, copy=False)
        return self.bundle.transformer.transform(frame)

    def p_attack(self, X: np.ndarray) -> np.ndarray:
        proba = self.bundle.rf_binary.predict_proba(X)
        classes = list(self.bundle.rf_binary.classes_)
        return proba[:, classes.index(1)] if 1 in classes else np.zeros(len(X))

    def anomaly_percentile(self, X: np.ndarray) -> np.ndarray:
        """Higher = more anomalous, as a percentile of the benign validation scores. 0.0 without an anomaly detector."""
        if not self.has_anomaly:
            return np.zeros(len(X))
        s = -self.bundle.iforest.score_samples(X)
        return 100.0 * np.searchsorted(self._sorted_scores, s, side="right") / len(self._sorted_scores)

    # --------------------------------------------------------------- full decision
    def detect(self, flows) -> Detections:
        frame = self._frame(flows)
        X = self.bundle.transformer.transform(frame) if frame is not None else self.transform(flows)
        raw = self.bundle.transformer.raw(frame) if frame is not None else None
        p, pct = self.p_attack(X), self.anomaly_percentile(X)
        n = len(X)
        family = [AttackFamily.BENIGN] * n
        closest: list[AttackFamily | None] = [None] * n
        fconf = np.full(n, np.nan)
        fprobs: list[dict[AttackFamily, float] | None] = [None] * n
        conf = np.zeros(n)
        verdict = [Verdict.BENIGN] * n

        flagged = np.flatnonzero(p >= self.tau_binary)
        multi = self.bundle.rf_multiclass
        if len(flagged) and multi is not None:
            proba = multi.predict_proba(X[flagged])
            classes = [AttackFamily(str(c)) for c in multi.classes_]
            for row, i in zip(proba, flagged, strict=True):
                probs = {c: float(q) for c, q in zip(classes, row, strict=True)}
                best = max(probs, key=probs.get)
                closest[i], fconf[i], fprobs[i] = best, probs[best], probs
        for i in range(n):
            v = fuse(float(p[i]), float(pct[i]), self.tau_binary, self.tau_anomaly,
                     None if np.isnan(fconf[i]) else float(fconf[i]), self.tau_family)
            verdict[i] = v
            if v is Verdict.KNOWN_ATTACK:
                conf[i] = p[i]
                family[i] = closest[i] if closest[i] is not None else AttackFamily.MALICIOUS
            elif v is Verdict.NOVEL_ANOMALY:
                family[i] = AttackFamily.UNKNOWN
                conf[i] = p[i] if p[i] >= self.tau_binary else novel_confidence(float(pct[i]), self.tau_anomaly)
        return Detections(verdict, p, pct, family, closest, fconf, fprobs, conf, X, raw)
