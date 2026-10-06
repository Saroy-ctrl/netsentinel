"""Incident brief generation service (M5-03).

Provides grounded incident briefings for SOC analysts using Azure OpenAI (gpt-4o-mini),
with a deterministic template fallback (source: 'template') when unconfigured, unreachable,
or timed out (strict 8s SLA).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from nscore.contracts.policy import (
    DEFAULT_SEVERITY,
    SEVERITY,
    confidence_band,
)
from nscore.contracts.policy import (
    mitre_for as policy_mitre_for,
)
from nscore.contracts.policy import (
    risk_level as policy_risk_level,
)
from nscore.contracts.policy import (
    risk_score as policy_risk_score,
)
from nscore.contracts.schemas import (
    AnalystActionRecord,
    AttackFamily,
    Brief,
    ConfidenceBand,
    FeatureContribution,
    IncidentDetail,
    IncidentStatus,
    RiskLevel,
    Verdict,
)

if TYPE_CHECKING:
    pass

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
        generated_at=datetime.now(UTC),
    )


def generate_brief(
    incident: IncidentDetail,
    refresh: bool = False,
    client: Any | None = None,
    timeout: float = LLM_TIMEOUT_SECONDS,
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

    effective_timeout = float(timeout) if timeout is not None else LLM_TIMEOUT_SECONDS

    try:
        response = aoai_client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, indent=2)},
            ],
            temperature=0.2,
            max_tokens=250,
            timeout=effective_timeout,
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
            generated_at=datetime.now(UTC),
        )
    except Exception as exc:
        logger.warning(
            f"Azure OpenAI call failed for incident {incident.incident_id} ({type(exc).__name__}: {exc}); "
            "falling back to template."
        )
        return generate_template_brief(incident)


def incident_data_to_incident_detail(
    incident_id: str,
    incident_data: dict[str, Any],
) -> IncidentDetail:
    """Convert an M3 database row or dictionary into a validated IncidentDetail structure."""
    inc_id = str(incident_id or incident_data.get("incident_id") or "unknown")

    # 1. Family & Verdict extraction and normalization
    raw_family = incident_data.get("attack_family")
    raw_verdict = incident_data.get("verdict")

    family: AttackFamily
    if isinstance(raw_family, AttackFamily):
        family = raw_family
    elif isinstance(raw_family, str):
        clean_fam = raw_family.strip()
        clean_fam_lower = clean_fam.lower()
        if clean_fam_lower in ("novel_anomaly", "unknown", "anomaly"):
            family = AttackFamily.UNKNOWN
        elif clean_fam_lower in ("malicious", "malware"):
            family = AttackFamily.MALICIOUS
        elif clean_fam_lower in ("ssh-bruteforce", "ftp-bruteforce", "bruteforce", "brute_force"):
            family = AttackFamily.BRUTE_FORCE
        elif clean_fam_lower in ("ddos", "ddos-hoic", "ddos-loic-http", "ddos-loic-udp"):
            family = AttackFamily.DDOS
        elif clean_fam_lower in ("dos", "dos-goldeneye", "dos-slowloris", "dos-hulk"):
            family = AttackFamily.DOS
        elif clean_fam_lower in ("webattack", "web_attack", "web-attack"):
            family = AttackFamily.WEB_ATTACK
        elif clean_fam_lower in ("portscan", "port_scan", "nmap"):
            family = AttackFamily.PORTSCAN
        elif clean_fam_lower == "botnet":
            family = AttackFamily.BOTNET
        elif clean_fam_lower == "infiltration":
            family = AttackFamily.INFILTRATION
        elif clean_fam_lower == "rare":
            family = AttackFamily.RARE
        elif clean_fam_lower == "benign":
            family = AttackFamily.BENIGN
        else:
            try:
                family = AttackFamily(clean_fam)
            except ValueError:
                family = AttackFamily.UNKNOWN if str(raw_verdict).lower() in ("anomaly", "novel_anomaly") else AttackFamily.MALICIOUS
    else:
        if str(raw_verdict).lower() in ("anomaly", "novel_anomaly"):
            family = AttackFamily.UNKNOWN
        elif str(raw_verdict).lower() == "benign":
            family = AttackFamily.BENIGN
        else:
            family = AttackFamily.MALICIOUS

    verdict: Verdict
    if isinstance(raw_verdict, Verdict):
        verdict = raw_verdict
    elif isinstance(raw_verdict, str):
        clean_v_lower = raw_verdict.strip().lower()
        if clean_v_lower in ("novel_anomaly", "anomaly"):
            verdict = Verdict.NOVEL_ANOMALY
        elif clean_v_lower == "benign":
            verdict = Verdict.BENIGN
        elif clean_v_lower in ("known_attack", "attack", "malicious"):
            verdict = Verdict.KNOWN_ATTACK
        else:
            verdict = Verdict.NOVEL_ANOMALY if family == AttackFamily.UNKNOWN else Verdict.KNOWN_ATTACK
    else:
        if family == AttackFamily.UNKNOWN:
            verdict = Verdict.NOVEL_ANOMALY
        elif family == AttackFamily.BENIGN:
            verdict = Verdict.BENIGN
        else:
            verdict = Verdict.KNOWN_ATTACK

    # 2. Status
    raw_status = incident_data.get("status", "new")
    status: IncidentStatus = (
        raw_status
        if raw_status in ("new", "acknowledged", "escalated", "dismissed_fp", "resolved")
        else "new"
    )

    # 3. MITRE technique mapping
    mitre_id = incident_data.get("mitre_technique_id") or incident_data.get("mitre_id")
    mitre_name = incident_data.get("mitre_technique_name") or incident_data.get("mitre_name")
    if not mitre_id or not mitre_name:
        default_mid, default_mname = policy_mitre_for(family)
        mitre_id = mitre_id or default_mid
        mitre_name = mitre_name or default_mname

    # 4. Confidence
    raw_conf = incident_data.get("max_confidence", incident_data.get("confidence", 0.85))
    try:
        max_confidence = max(0.0, min(1.0, float(raw_conf)))
    except (ValueError, TypeError):
        max_confidence = 0.85

    # 5. Severity
    raw_sev = incident_data.get("severity")
    if raw_sev is not None:
        try:
            severity = max(0.0, min(1.0, float(raw_sev)))
        except (ValueError, TypeError):
            severity = SEVERITY.get(family, DEFAULT_SEVERITY)
    else:
        severity = SEVERITY.get(family, DEFAULT_SEVERITY)

    # 6. Flow count
    try:
        flow_count = max(1, int(incident_data.get("flow_count", 1)))
    except (ValueError, TypeError):
        flow_count = 1

    # 7. Risk score and level
    raw_score = incident_data.get("risk_score")
    if raw_score is not None:
        try:
            risk_score = max(0, min(100, int(raw_score)))
        except (ValueError, TypeError):
            risk_score = policy_risk_score(verdict, max_confidence, severity, flow_count)
    else:
        risk_score = policy_risk_score(verdict, max_confidence, severity, flow_count)

    raw_level = incident_data.get("risk_level")
    if raw_level in ("HIGH", "MEDIUM", "LOW"):
        risk_level: RiskLevel = raw_level
    else:
        risk_level = policy_risk_level(risk_score)

    # 8. Endpoints
    src_ip = str(incident_data.get("src_ip", "0.0.0.0"))
    dst_ip = str(incident_data.get("dst_ip", "0.0.0.0"))
    try:
        dst_port = int(incident_data.get("dst_port", 0))
    except (ValueError, TypeError):
        dst_port = 0

    # 9. Timestamps
    def parse_dt(val: Any) -> datetime:
        if isinstance(val, datetime):
            return val if val.tzinfo is not None else val.replace(tzinfo=UTC)
        if isinstance(val, str) and val.strip():
            try:
                s = val.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(s)
                return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
            except Exception:
                pass
        return datetime.now(UTC)

    first_seen = parse_dt(incident_data.get("first_seen"))
    last_seen = parse_dt(incident_data.get("last_seen"))

    # 10. Model version
    model_version = str(incident_data.get("model_version", "1.0.0"))

    # 11. Top features
    top_features: list[FeatureContribution] = []
    raw_tf = incident_data.get("top_features")
    if raw_tf is None and "top_features_json" in incident_data:
        raw_tf_json = incident_data.get("top_features_json")
        if isinstance(raw_tf_json, str) and raw_tf_json.strip():
            try:
                raw_tf = json.loads(raw_tf_json)
            except Exception:
                raw_tf = []
        elif isinstance(raw_tf_json, list):
            raw_tf = raw_tf_json

    if isinstance(raw_tf, list):
        for item in raw_tf[:10]:
            if isinstance(item, FeatureContribution):
                top_features.append(item)
            elif isinstance(item, dict):
                try:
                    f_dict = dict(item)
                    if "feature" in f_dict:
                        f_dict["value"] = float(f_dict.get("value", 0.0))
                        f_dict["shap_value"] = float(f_dict.get("shap_value", 0.0))
                        if f_dict.get("baseline_median") is not None:
                            f_dict["baseline_median"] = float(f_dict["baseline_median"])
                        top_features.append(FeatureContribution.model_validate(f_dict))
                except Exception:
                    pass

    # 12. Sample flow IDs and analyst actions
    sample_flow_ids = [str(x) for x in incident_data.get("sample_flow_ids", [])][:20]
    actions: list[AnalystActionRecord] = []
    raw_actions = incident_data.get("actions", [])
    if isinstance(raw_actions, list):
        for act in raw_actions:
            if isinstance(act, AnalystActionRecord):
                actions.append(act)
            elif isinstance(act, dict):
                try:
                    actions.append(AnalystActionRecord.model_validate(act))
                except Exception:
                    pass

    # 13. Cached brief if provided
    brief_obj: Brief | None = None
    raw_brief = incident_data.get("brief")
    if raw_brief is None and "brief_json" in incident_data:
        raw_bj = incident_data.get("brief_json")
        if isinstance(raw_bj, str) and raw_bj.strip():
            try:
                raw_brief = json.loads(raw_bj)
            except Exception:
                pass
        elif isinstance(raw_bj, dict):
            raw_brief = raw_bj

    if isinstance(raw_brief, Brief):
        brief_obj = raw_brief
    elif isinstance(raw_brief, dict):
        try:
            brief_obj = Brief.model_validate(raw_brief)
        except Exception:
            pass

    return IncidentDetail(
        incident_id=inc_id,
        status=status,
        verdict=verdict,
        attack_family=family,
        mitre_technique_id=mitre_id,
        mitre_technique_name=mitre_name,
        risk_score=risk_score,
        risk_level=risk_level,
        severity=severity,
        max_confidence=max_confidence,
        flow_count=flow_count,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        first_seen=first_seen,
        last_seen=last_seen,
        model_version=model_version,
        top_features=top_features,
        sample_flow_ids=sample_flow_ids,
        actions=actions,
        brief=brief_obj,
    )


async def generate_and_cache_brief(
    incident_id: str,
    incident_data: dict[str, Any],
    repo: Any = None,
    refresh: bool = False,
    timeout: float = LLM_TIMEOUT_SECONDS,
    client: Any | None = None,
) -> Brief:
    """Generate an incident brief and cache it through the repository.

    M3-compatible async wrapper that preserves M5 generate_brief() as the source of truth,
    converts M3 row dicts into IncidentDetail, respects caller timeouts, and persists
    the resulting brief to repo.update_incident_brief() when available.
    """
    # 1. Return cached brief if refresh=False
    if not refresh:
        if incident_data.get("brief_json"):
            try:
                raw_bj = incident_data["brief_json"]
                data = json.loads(raw_bj) if isinstance(raw_bj, str) else raw_bj
                return Brief.model_validate(data)
            except Exception as exc:
                logger.warning(f"Failed to parse cached brief_json for incident {incident_id}: {exc}")

        if incident_data.get("brief"):
            raw_b = incident_data["brief"]
            if isinstance(raw_b, Brief):
                return raw_b
            if isinstance(raw_b, dict):
                try:
                    return Brief.model_validate(raw_b)
                except Exception as exc:
                    logger.warning(f"Failed to parse cached brief for incident {incident_id}: {exc}")

    # 2. Convert to grounded IncidentDetail structure
    incident = incident_data_to_incident_detail(incident_id, incident_data)
    effective_timeout = float(timeout) if timeout is not None else LLM_TIMEOUT_SECONDS

    # 3. Define generation coroutine executed under caller timeout
    async def _execute_generation() -> Brief:
        return await asyncio.to_thread(
            generate_brief,
            incident,
            refresh=True,
            client=client,
            timeout=effective_timeout,
        )

    # 4. Generate brief via M5 source of truth with timeout
    try:
        brief = await asyncio.wait_for(_execute_generation(), timeout=effective_timeout)
    except TimeoutError:
        logger.warning(
            f"Brief generation timed out after {effective_timeout}s for incident {incident_id}; "
            "falling back to template."
        )
        template_brief = generate_template_brief(incident)
        brief = Brief(
            incident_id=incident.incident_id,
            text=f"Fallback deterministic template brief for incident {incident_id}. {template_brief.text}",
            source="template",
            model_deployment=None,
            confidence_band="low",
            generated_at=datetime.now(UTC),
        )

    # 5. Persist brief to repository when update_incident_brief is present
    if repo is not None and hasattr(repo, "update_incident_brief"):
        try:
            brief_json = brief.model_dump_json()
            res = repo.update_incident_brief(incident_id, brief_json)
            if asyncio.iscoroutine(res):
                await res
        except Exception as exc:
            logger.warning(f"Failed to persist brief to repository for {incident_id}: {exc}")

    return brief
