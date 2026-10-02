"""Shared SOC policy: MITRE mapping, severity, priority and confidence bands.

Pure functions, no I/O. Owned by M5 (values) + M3 (usage). Values are a
defensible first cut; M5-01 validates/adjusts them and documents why.
"""

from __future__ import annotations

import math

from .schemas import AttackFamily, ConfidenceBand, PriorityBand, Verdict

# MITRE ATT&CK enterprise techniques. Family -> (technique id, name)
MITRE_MAP: dict[AttackFamily, tuple[str, str]] = {
    AttackFamily.PORTSCAN: ("T1046", "Network Service Discovery"),
    AttackFamily.BRUTE_FORCE: ("T1110", "Brute Force"),
    AttackFamily.DOS: ("T1499", "Endpoint Denial of Service"),
    AttackFamily.DDOS: ("T1498", "Network Denial of Service"),
    AttackFamily.WEB_ATTACK: ("T1190", "Exploit Public-Facing Application"),
    AttackFamily.BOTNET: ("T1071", "Application Layer Protocol (C2)"),
}

# 0..1 business severity of a confirmed instance of each family
SEVERITY: dict[AttackFamily, float] = {
    AttackFamily.BOTNET: 0.90,
    AttackFamily.WEB_ATTACK: 0.85,
    AttackFamily.RARE: 0.85,
    AttackFamily.DDOS: 0.80,
    AttackFamily.UNKNOWN: 0.75,  # novel anomaly: unknown = treat seriously, but below confirmed C2
    AttackFamily.DOS: 0.75,
    AttackFamily.BRUTE_FORCE: 0.70,
    AttackFamily.PORTSCAN: 0.45,
    AttackFamily.BENIGN: 0.0,
}

NOVELTY_BONUS = 0.10


def mitre_for(family: AttackFamily) -> tuple[str | None, str | None]:
    return MITRE_MAP.get(family, (None, None))


def priority_score(
    family: AttackFamily, verdict: Verdict, confidence: float, flow_count: int
) -> int:
    """0..100 = severity x confidence x volume (+ novelty bonus).

    volume is in [0.85, 1.0]: 1 flow -> 0.85, >=1000 flows -> 1.0 (log scale),
    so a big burst nudges priority up without drowning out severity.
    """
    if verdict is Verdict.BENIGN:
        return 0
    volume = 0.85 + 0.15 * min(1.0, math.log10(max(flow_count, 1)) / 3)
    bonus = NOVELTY_BONUS if verdict is Verdict.NOVEL_ANOMALY else 0.0
    raw = SEVERITY.get(family, 0.5) * confidence * volume + bonus
    return round(100 * min(max(raw, 0.0), 1.0))


def priority_band(score: int) -> PriorityBand:
    if score >= 75:
        return "P1"
    if score >= 55:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"


def confidence_band(confidence: float) -> ConfidenceBand:
    """Drives LLM hedging: low band -> 'possible', 'worth reviewing'."""
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.60:
        return "medium"
    return "low"
