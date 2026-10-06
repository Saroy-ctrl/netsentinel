"""Incident brief generation service (M5-03).

Provides grounded incident briefings for SOC analysts using Azure OpenAI (gpt-4o-mini),
with a deterministic template fallback (source: 'template') when unconfigured, unreachable,
or timed out (strict 8s SLA).
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from nscore.contracts.policy import confidence_band
from nscore.contracts.schemas import (
    AttackFamily,
    Brief,
    ConfidenceBand,
    FeatureContribution,
    IncidentDetail,
    Verdict,
)

if TYPE_CHECKING:
    from openai import AzureOpenAI

logger = logging.getLogger(__name__)

LLM_TIMEOUT_SECONDS: float = 8.0
DEFAULT_DEPLOYMENT: str = "gpt-4o-mini"
DEFAULT_API_VERSION: str = "2024-10-21"

# Module-level singleton client cache
_cached_client: Any = None
_client_initialized: bool = False

# Canonical suggested next steps from docs/threat_model.md §7
PLAYBOOK_ACTIONS: dict[AttackFamily, str] = {
    AttackFamily.INFILTRATION: (
        "Isolate the source host from the internal network immediately and inspect "
        "host process trees and outbound connections for initial compromise artifacts."
    ),
    AttackFamily.BOTNET: (
        "Quarantine the infected host, block destination C2 IP/domain at perimeter firewalls/DNS sinkhole, "
        "and review memory/persistence mechanisms on the endpoint."
    ),
    AttackFamily.DDOS: (
        "Activate upstream volumetric DDoS mitigation/scrubbing rules, rate-limit incoming traffic "
        "at border routers, and monitor edge gateway saturation."
    ),
    AttackFamily.DOS: (
        "Apply rate limiting or temporary IP blocks for the offending source on target web/application "
        "servers and inspect service resource utilization."
    ),
    AttackFamily.BRUTE_FORCE: (
        "Enforce IP rate-limiting and temporary account lockout on the target authentication service (SSH/FTP), "
        "and review auth logs for unauthorized logins."
    ),
    AttackFamily.WEB_ATTACK: (
        "Inspect web application firewall (WAF) and web server access logs for SQL injection or XSS payloads, "
        "verify input sanitization, and confirm application patch status."
    ),
    AttackFamily.PORTSCAN: (
        "Add offending external IP to perimeter edge monitoring watchlists or firewall temporary drop rules "
        "if volume exceeds reconnaissance thresholds."
    ),
    AttackFamily.RARE: (
        "Initiate tier-2 manual triage, extract full packet captures (PCAP) for the unusual flow signature, "
        "and correlate with endpoint telemetry."
    ),
    AttackFamily.MALICIOUS: (
        "Check the external IP against threat intelligence feeds, block at network boundary, and inspect "
        "internal host connection logs for follow-up staging."
    ),
    AttackFamily.UNKNOWN: (
        "Review top SHAP feature deviations against normal traffic baselines, capture PCAP for deep packet "
        "inspection, and verify whether the flow represents an unmodeled protocol or zero-day behavior."
    ),
    AttackFamily.BENIGN: (
        "No action required; flow logged to rolling baseline buffer for statistical drift monitoring."
    ),
}

DEFAULT_PLAYBOOK_ACTION: str = (
    "Review incident network telemetry and correlate with host logs before escalating."
)

SYSTEM_PROMPT = """You are NetSentinel's security incident summariser.
Generate a concise, professional 3-4 sentence incident brief for a SOC analyst based SOLELY on the provided structured incident JSON.

Strict guidelines:
1. Grounding: Do NOT invent, assume, or extrapolate any details, CVEs, payload contents, host processes, or user accounts not explicitly provided in the input.
2. Structure:
   - Sentence 1 (Observation): What was seen (source IP, destination IP, destination port, flow count, and attack family/verdict).
   - Sentence 2-3 (Evidence): Why it was flagged, explaining the statistical anomalies in the provided top features compared to the normal baselines.
   - Sentence 4 (Next step): One concrete suggested next step for the analyst based on the attack family.
3. Hedging & Confidence:
   - Match your tone to the provided confidence_band:
     - 'high': Assertive, confirmed ("Confirmed...", "Active...").
     - 'medium': Probable, measured ("Likely...", "Probable...").
     - 'low': Cautious, investigative ("Possible...", "Potential...", "Worth reviewing before escalating...").
4. Verdict-Specific Rules:
   - If verdict is 'novel_anomaly' or family is 'Unknown': State plainly that no known attack family matched and traffic sits outside normal behaviour. Do not guess or assign an unverified attack family.
   - If family is 'Malicious' (binary-only classification): State that the traffic was flagged as malicious per threat intelligence, but do NOT guess or assign a specific attack family or exploit type.
5. Formatting: Output plain text only. Exactly 3 to 4 sentences. No markdown headers, bullet points, or conversational filler.
"""


def reset_client_cache() -> None:
    """Reset the cached Azure OpenAI client singleton (used for testing and configuration reload)."""
    global _cached_client, _client_initialized
    _cached_client = None
    _client_initialized = False


def get_azure_openai_client() -> Any | None:
    """Lazily instantiate and cache the AzureOpenAI client from environment variables."""
    global _cached_client, _client_initialized
    if _client_initialized:
        return _cached_client

    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip()
    api_key = os.getenv("AZURE_OPENAI_API_KEY", "").strip()
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", DEFAULT_API_VERSION).strip() or DEFAULT_API_VERSION

    if not endpoint or not api_key:
        logger.info("Azure OpenAI credentials not fully configured; using template fallback.")
        _cached_client = None
        _client_initialized = True
        return None

    try:
        from openai import AzureOpenAI

        _cached_client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version,
            timeout=LLM_TIMEOUT_SECONDS,
        )
        _client_initialized = True
        return _cached_client
    except Exception as exc:
        logger.warning(f"Failed to initialize AzureOpenAI client: {exc}")
        _cached_client = None
        _client_initialized = True
        return None


def format_feature_deviations(top_features: list[FeatureContribution]) -> str:
    """Format the top feature anomalies compared to benign medians."""
    if not top_features:
        return "telemetry exhibited statistical deviation from normal traffic baselines"

    items: list[str] = []
    for feat in top_features[:2]:
        name = feat.feature.replace("_", " ")
        val = feat.value
        median = feat.baseline_median
        if median is not None and median > 0:
            ratio = val / median
            if ratio >= 3.0:
                items.append(f"{name} is ~{ratio:,.0f}x higher than typical")
            elif ratio <= 0.33 and val > 0:
                inv_ratio = 1.0 / ratio
                items.append(f"{name} is ~{inv_ratio:,.0f}x lower than typical")
            elif val == 0:
                items.append(f"{name} is zero (typical baseline {median:,.1f})")
            else:
                items.append(f"{name} is {val:,.1f} vs baseline {median:,.1f}")
        elif median == 0.0 and val > 0:
            items.append(f"{name} is elevated ({val:,.1f} vs normal 0)")
        else:
            items.append(f"{name} is {val:,.1f}")

    if items:
        return ": " + " and ".join(items)
    return "telemetry exhibited statistical deviation from normal traffic baselines"


def generate_template_brief(incident: IncidentDetail) -> Brief:
    """Generate a deterministic template brief from structured incident fields."""
    band: ConfidenceBand = confidence_band(incident.max_confidence)
    flows_str = f"{incident.flow_count:,} flow{'s' if incident.flow_count != 1 else ''}"
    playbook_action = PLAYBOOK_ACTIONS.get(incident.attack_family, DEFAULT_PLAYBOOK_ACTION)
    feature_summary = format_feature_deviations(incident.top_features)

    # Sentence 1: Observation hedged by confidence band
    if incident.verdict == Verdict.NOVEL_ANOMALY or incident.attack_family == AttackFamily.UNKNOWN:
        if band == "high":
            s1 = (
                f"High-confidence anomalous activity observed from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        elif band == "medium":
            s1 = (
                f"Probable novel activity from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        else:
            s1 = (
                f"Possible novel activity from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        s2 = f"No known attack family matched, but the traffic sits far outside normal behaviour{feature_summary}."
        if band == "low":
            s3 = f"Worth reviewing: check what {incident.src_ip} is doing on port {incident.dst_port} before escalating."
        else:
            s3 = f"Recommended action: {playbook_action}"

    elif incident.attack_family == AttackFamily.MALICIOUS:
        if band == "high":
            s1 = (
                f"Confirmed malicious network activity from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        elif band == "medium":
            s1 = (
                f"Likely malicious network activity from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        else:
            s1 = (
                f"Possible malicious network activity from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        s2 = f"The traffic was flagged as malicious per threat intelligence with unclassified exploit structure{feature_summary}."
        if band == "high":
            s3 = f"Immediate action required: {playbook_action}"
        elif band == "medium":
            s3 = f"Recommended action: {playbook_action}"
        else:
            s3 = f"Worth reviewing before escalating: {playbook_action}"

    else:
        # Known attack family
        family_name = incident.attack_family.value
        mitre_suffix = f" (MITRE {incident.mitre_technique_id})" if incident.mitre_technique_id else ""
        if band == "high":
            s1 = (
                f"Active {family_name}{mitre_suffix} activity detected from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        elif band == "medium":
            s1 = (
                f"Likely {family_name}{mitre_suffix} activity observed from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        else:
            s1 = (
                f"Possible {family_name}{mitre_suffix} activity detected from {incident.src_ip} "
                f"to {incident.dst_ip}:{incident.dst_port} across {flows_str}."
            )
        s2 = f"The traffic matches {family_name} behavioral patterns{feature_summary}."
        if band == "high":
            s3 = f"Immediate action required: {playbook_action}"
        elif band == "medium":
            s3 = f"Recommended action: {playbook_action}"
        else:
            s3 = f"Worth reviewing before escalating: {playbook_action}"

    text = f"{s1} {s2} {s3}"
    return Brief(
        incident_id=incident.incident_id,
        text=text,
        source="template",
        model_deployment=None,
        confidence_band=band,
        generated_at=datetime.now(timezone.utc),
    )


def generate_brief(
    incident: IncidentDetail,
    refresh: bool = False,
    client: Any | None = None,
) -> Brief:
    """Generate an incident brief, using Azure OpenAI with an 8s timeout and falling back to template."""
    if not refresh and incident.brief is not None:
        return incident.brief

    band: ConfidenceBand = confidence_band(incident.max_confidence)
    aoai_client = client if client is not None else get_azure_openai_client()

    if aoai_client is None:
        return generate_template_brief(incident)

    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", DEFAULT_DEPLOYMENT).strip() or DEFAULT_DEPLOYMENT
    payload: dict[str, Any] = {
        "incident_id": incident.incident_id,
        "verdict": incident.verdict.value,
        "attack_family": incident.attack_family.value,
        "confidence_band": band,
        "max_confidence": round(incident.max_confidence, 3),
        "risk_score": incident.risk_score,
        "risk_level": incident.risk_level,
        "flow_count": incident.flow_count,
        "src_ip": incident.src_ip,
        "dst_ip": incident.dst_ip,
        "dst_port": incident.dst_port,
        "mitre_technique_id": incident.mitre_technique_id,
        "mitre_technique_name": incident.mitre_technique_name,
        "top_features": [
            {
                "feature": f.feature,
                "value": round(f.value, 4),
                "shap_value": round(f.shap_value, 4),
                "baseline_median": round(f.baseline_median, 4) if f.baseline_median is not None else None,
            }
            for f in incident.top_features[:5]
        ],
        "suggested_playbook_action": PLAYBOOK_ACTIONS.get(incident.attack_family, DEFAULT_PLAYBOOK_ACTION),
    }

    try:
        response = aoai_client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, indent=2)},
            ],
            temperature=0.2,
            max_tokens=250,
            timeout=LLM_TIMEOUT_SECONDS,
        )
        content = (response.choices[0].message.content or "").strip()
        if not content:
            logger.warning(
                f"Azure OpenAI returned empty response for {incident.incident_id}; using template fallback."
            )
            return generate_template_brief(incident)

        return Brief(
            incident_id=incident.incident_id,
            text=content,
            source="azure_openai",
            model_deployment=deployment,
            confidence_band=band,
            generated_at=datetime.now(timezone.utc),
        )
    except Exception as exc:
        logger.warning(
            f"Azure OpenAI call failed for incident {incident.incident_id} ({type(exc).__name__}: {exc}); "
            "falling back to template."
        )
        return generate_template_brief(incident)
