"""Verdict rule shared by evaluation and the API (owner: M2).

Evidence-based design (docs/experiments.md): on CIC-IDS2018 a benign-only IsolationForest has ~0 recall at a sane
false-alarm rate, while the supervised binary RF still detects attack FAMILIES and TOOLS it was never trained on, and
the family head's confidence cleanly separates unfamiliar attacks from familiar ones (ROC-AUC ~0.999). So:

  p_attack >= tau_binary                          the flow is an attack
      family_conf <  tau_family                   -> NOVEL_ANOMALY  (unfamiliar attack; closest known family reported)
      otherwise                                   -> KNOWN_ATTACK
  p_attack <  tau_binary
      anomaly_percentile >= tau_anomaly           -> NOVEL_ANOMALY  (optional benign-only detector; tau_anomaly > 100
                                                     disables it, which is the default for CIC bundles)
      otherwise                                   -> BENIGN

Binary-only bundles (LUFlow, no family head) pass family_conf=None and rely on the optional anomaly path for novelty.
"""

from __future__ import annotations

from nscore.contracts.schemas import Verdict

ANOMALY_DISABLED = 101.0  # percentile can never reach this


def fuse(p_attack: float, anomaly_percentile: float, tau_binary: float, tau_anomaly: float = ANOMALY_DISABLED,
         family_conf: float | None = None, tau_family: float = 0.0) -> Verdict:
    if p_attack >= tau_binary:
        if family_conf is not None and family_conf < tau_family:
            return Verdict.NOVEL_ANOMALY
        return Verdict.KNOWN_ATTACK
    if anomaly_percentile >= tau_anomaly:
        return Verdict.NOVEL_ANOMALY
    return Verdict.BENIGN


def novel_confidence(anomaly_percentile: float, tau_anomaly: float) -> float:
    """Map anomaly percentile in [tau, 100] onto a [0.5, 1.0] confidence for the risk engine / brief hedging."""
    if anomaly_percentile < tau_anomaly or tau_anomaly >= 100:
        return 0.0
    return 0.5 + 0.5 * (anomaly_percentile - tau_anomaly) / (100 - tau_anomaly)
