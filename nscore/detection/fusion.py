"""Two-detector fusion: the core of "catch what signatures miss".

  RF binary head      -> knows what attacks in the training set look like
  IsolationForest     -> trained on BENIGN only; knows what normal looks like

  p_attack >= tau_binary                         -> KNOWN_ATTACK   (family from multiclass head)
  p_attack <  tau_binary and anomaly >= tau_anom -> NOVEL_ANOMALY  (family = Unknown)
  otherwise                                      -> BENIGN

Both thresholds are picked on the validation split to meet an explicit
benign false-positive budget (M2-07), never left at 0.5.
Owner: M2. Consumers: ml/evaluate (LOAO), api scoring.
"""

from __future__ import annotations

from nscore.contracts.schemas import Verdict


def fuse(p_attack: float, anomaly_percentile: float, tau_binary: float, tau_anomaly: float) -> Verdict:
    if p_attack >= tau_binary:
        return Verdict.KNOWN_ATTACK
    if anomaly_percentile >= tau_anomaly:
        return Verdict.NOVEL_ANOMALY
    return Verdict.BENIGN


def novel_confidence(anomaly_percentile: float, tau_anomaly: float) -> float:
    """Map anomaly percentile in [tau, 100] onto a [0.5, 1.0] confidence for priority/hedging."""
    if anomaly_percentile < tau_anomaly or tau_anomaly >= 100:
        return 0.0
    return 0.5 + 0.5 * (anomaly_percentile - tau_anomaly) / (100 - tau_anomaly)
