"""Risk engine: how urgently should an analyst care about this incident?

Merges the team's Risk Scoring Pipeline doc (docs/reference/NetSentinel_Risk_Scoring_Pipeline.pdf)
with the incident/novelty design in docs/03_architecture.md #4.4.

    severity   = sum_f P(f | attack) * W[f]        expected severity over the family head's probabilities
                 (binary-only bundle -> W[Malicious], novel anomaly -> W[Unknown])
    confidence = p_attack (known attack)  |  novel_confidence(anomaly percentile) (novel anomaly)
    burst      = 1 + 0.15 * min(1, log10(flow_count) / 3)     1 flow -> 1.00, >= 1000 flows -> 1.15
    risk       = round(100 * (confidence * severity * burst + novelty_bonus)), capped at 100
    level      = HIGH >= 70 | MEDIUM 40-69 | LOW < 40

Confidence measures certainty, severity measures consequence: a model can be very sure about
something harmless. SHAP never changes the score; it explains why the flow was flagged.

Pure functions, no I/O. Weights are owned by M5 (justified in docs/threat_model.md).
"""

from __future__ import annotations

import math
from collections.abc import Mapping

from .schemas import AttackFamily, ConfidenceBand, RiskLevel, Verdict

# Damage if the alert is real (0..1). Base values from the team's risk-scoring doc.
SEVERITY: dict[AttackFamily, float] = {
    AttackFamily.INFILTRATION: 1.00,  # attacker already inside
    AttackFamily.BOTNET: 0.90,  # a host is likely already compromised
    AttackFamily.DDOS: 0.80,  # service disruption, high visibility
    AttackFamily.DOS: 0.80,
    AttackFamily.RARE: 0.80,  # merged rare families: treat as serious until triaged
    AttackFamily.UNKNOWN: 0.75,  # novel anomaly: unknown intent, plus NOVELTY_BONUS below
    AttackFamily.BRUTE_FORCE: 0.70,  # active attempt to gain access
    AttackFamily.MALICIOUS: 0.70,  # binary-only bundle (LUFlow): malicious, type unknown
    AttackFamily.WEB_ATTACK: 0.60,  # could mean an exploited app, often fails
    AttackFamily.PORTSCAN: 0.30,  # reconnaissance only
    AttackFamily.BENIGN: 0.0,
}
DEFAULT_SEVERITY = 0.5
NOVELTY_BONUS = 0.10
BURST_MAX_BOOST = 0.15

# MITRE ATT&CK enterprise techniques. Family -> (technique id, name). M5-01 validates.
MITRE_MAP: dict[AttackFamily, tuple[str, str]] = {
    AttackFamily.BRUTE_FORCE: ("T1110", "Brute Force"),
    AttackFamily.DOS: ("T1499", "Endpoint Denial of Service"),
    AttackFamily.DDOS: ("T1498", "Network Denial of Service"),
    AttackFamily.WEB_ATTACK: ("T1190", "Exploit Public-Facing Application"),
    AttackFamily.INFILTRATION: ("T1046", "Network Service Discovery (internal, post-compromise)"),
    AttackFamily.BOTNET: ("T1071", "Application Layer Protocol (C2)"),
    AttackFamily.PORTSCAN: ("T1046", "Network Service Discovery"),
}


def mitre_for(family: AttackFamily) -> tuple[str | None, str | None]:
    return MITRE_MAP.get(family, (None, None))


def expected_severity(family: AttackFamily, family_probs: Mapping[AttackFamily, float] | None = None) -> float:
    """Probability-weighted severity, so an unsure WebAttack-vs-Infiltration call isn't scored as either extreme."""
    if not family_probs:
        return SEVERITY.get(family, DEFAULT_SEVERITY)
    total = sum(family_probs.values())
    if total <= 0:
        return SEVERITY.get(family, DEFAULT_SEVERITY)
    return sum(p * SEVERITY.get(f, DEFAULT_SEVERITY) for f, p in family_probs.items()) / total


def burst_factor(flow_count: int) -> float:
    """Team doc's 'Factor 3' at incident level: repeated flows nudge risk up, never down."""
    return 1 + BURST_MAX_BOOST * min(1.0, math.log10(max(flow_count, 1)) / 3)


def risk_score(verdict: Verdict, confidence: float, severity: float, flow_count: int = 1) -> int:
    if verdict is Verdict.BENIGN:
        return 0
    bonus = NOVELTY_BONUS if verdict is Verdict.NOVEL_ANOMALY else 0.0
    raw = confidence * severity * burst_factor(flow_count) + bonus
    return round(100 * min(max(raw, 0.0), 1.0))


def risk_level(score: int) -> RiskLevel:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def confidence_band(confidence: float) -> ConfidenceBand:
    """Drives LLM hedging: low band -> 'possible', 'worth reviewing'."""
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.60:
        return "medium"
    return "low"
