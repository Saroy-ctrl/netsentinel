"""Unit tests for incident brief service (M5-03).

Tests LLM brief generation with a stubbed Azure OpenAI client,
deterministic template fallback, 8-second timeout handling,
confidence-band hedging, novel-anomaly wording, and contract validation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from api.app.services.brief import (
    DEFAULT_DEPLOYMENT,
    LLM_TIMEOUT_SECONDS,
    PLAYBOOK_ACTIONS,
    format_feature_deviations,
    generate_brief,
    generate_template_brief,
    get_azure_openai_client,
    reset_client_cache,
)
from nscore.contracts import schemas as s

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nscore"
    / "contracts"
    / "fixtures"
    / "incident_detail.json"
)


@pytest.fixture
def sample_incident() -> s.IncidentDetail:
    """Load the canonical incident_detail fixture."""
    data = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return s.IncidentDetail.model_validate(data)


@pytest.fixture(autouse=True)
def clean_client_cache():
    """Ensure Azure OpenAI client cache is reset before and after each test."""
    reset_client_cache()
    yield
    reset_client_cache()


def _make_mock_client(return_text: str | None = "Mocked LLM brief.", side_effect: Exception | None = None) -> Any:
    """Create a stubbed AzureOpenAI client."""
    client = MagicMock()
    if side_effect:
        client.chat.completions.create.side_effect = side_effect
    else:
        choice = MagicMock()
        choice.message.content = return_text
        response = MagicMock()
        response.choices = [choice]
        client.chat.completions.create.return_value = response
    return client


# --------------------------------------------------------------------------- Tests


def test_template_brief_from_fixture(sample_incident: s.IncidentDetail):
    """Template generator must produce a valid Brief adhering to the contract schema."""
    brief = generate_template_brief(sample_incident)

    assert isinstance(brief, s.Brief)
    assert brief.incident_id == sample_incident.incident_id
    assert brief.source == "template"
    assert brief.model_deployment is None
    assert brief.confidence_band == "medium"
    assert brief.generated_at.tzinfo is not None

    # Sentence checks
    assert sample_incident.src_ip in brief.text
    assert str(sample_incident.dst_port) in brief.text
    assert "No known attack family matched" in brief.text
    assert "Worth reviewing" in brief.text or "Recommended action" in brief.text


def test_generate_brief_cached_behavior(sample_incident: s.IncidentDetail):
    """When incident.brief is already set and refresh=False, return cached brief without calling client."""
    existing_brief = sample_incident.brief
    assert existing_brief is not None

    mock_client = _make_mock_client(return_text="New generation should not happen.")
    brief = generate_brief(sample_incident, refresh=False, client=mock_client)

    assert brief == existing_brief
    mock_client.chat.completions.create.assert_not_called()


def test_generate_brief_refresh(sample_incident: s.IncidentDetail):
    """When refresh=True, bypass cache and generate a new brief."""
    mock_client = _make_mock_client(return_text="Fresh LLM brief on refresh.")
    brief = generate_brief(sample_incident, refresh=True, client=mock_client)

    assert brief.source == "azure_openai"
    assert brief.text == "Fresh LLM brief on refresh."
    assert mock_client.chat.completions.create.call_count == 1


def test_generate_brief_fallback_when_unconfigured(sample_incident: s.IncidentDetail, monkeypatch):
    """When Azure credentials are empty, cleanly fall back to template brief."""
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)

    brief = generate_brief(sample_incident, refresh=True, client=None)

    assert brief.source == "template"
    assert brief.model_deployment is None
    assert brief.incident_id == sample_incident.incident_id
    assert sample_incident.src_ip in brief.text


def test_generate_brief_with_stubbed_client(sample_incident: s.IncidentDetail):
    """Verify that a successful client call populates source='azure_openai' and model_deployment."""
    mock_client = _make_mock_client(
        return_text="Confirmed novel activity observed from 18.219.211.138 to 172.31.69.25:8080."
    )

    brief = generate_brief(sample_incident, refresh=True, client=mock_client)

    assert brief.source == "azure_openai"
    assert brief.model_deployment == DEFAULT_DEPLOYMENT
    assert brief.confidence_band == "medium"
    assert "Confirmed novel activity" in brief.text

    # Verify timeout parameter
    kwargs = mock_client.chat.completions.create.call_args.kwargs
    assert kwargs["timeout"] == LLM_TIMEOUT_SECONDS
    assert kwargs["model"] == DEFAULT_DEPLOYMENT

    # Verify grounded payload contains only structured fields
    user_payload = json.loads(kwargs["messages"][1]["content"])
    assert user_payload["incident_id"] == sample_incident.incident_id
    assert user_payload["src_ip"] == sample_incident.src_ip
    assert user_payload["flow_count"] == sample_incident.flow_count
    assert "top_features" in user_payload
    assert "suggested_playbook_action" in user_payload


def test_generate_brief_timeout_fallback(sample_incident: s.IncidentDetail):
    """When Azure OpenAI times out (>8s SLA), catch timeout and return template brief."""
    mock_client = _make_mock_client(side_effect=TimeoutError("Request timed out after 8.0s"))

    brief = generate_brief(sample_incident, refresh=True, client=mock_client)

    assert brief.source == "template"
    assert brief.model_deployment is None
    assert brief.incident_id == sample_incident.incident_id
    assert sample_incident.src_ip in brief.text


def test_generate_brief_api_error_fallback(sample_incident: s.IncidentDetail):
    """When Azure OpenAI returns an API error (500 or rate limit), fall back to template."""
    mock_client = _make_mock_client(side_effect=RuntimeError("Azure OpenAI 500 Internal Server Error"))

    brief = generate_brief(sample_incident, refresh=True, client=mock_client)

    assert brief.source == "template"
    assert brief.model_deployment is None
    assert brief.incident_id == sample_incident.incident_id


def test_generate_brief_empty_content_fallback(sample_incident: s.IncidentDetail):
    """If Azure OpenAI returns an empty string or whitespace, fall back to template."""
    mock_client = _make_mock_client(return_text="   ")

    brief = generate_brief(sample_incident, refresh=True, client=mock_client)

    assert brief.source == "template"
    assert brief.model_deployment is None
    assert len(brief.text) > 20


def test_confidence_band_hedging(sample_incident: s.IncidentDetail):
    """Verify confidence band tone hedging in templates across high, medium, and low bands."""
    # High confidence (>= 0.85)
    incident_high = sample_incident.model_copy(
        update={"max_confidence": 0.95, "attack_family": s.AttackFamily.BRUTE_FORCE, "verdict": s.Verdict.KNOWN_ATTACK}
    )
    brief_high = generate_template_brief(incident_high)
    assert brief_high.confidence_band == "high"
    assert "Active BruteForce" in brief_high.text
    assert "Immediate action required" in brief_high.text

    # Medium confidence (0.60 <= conf < 0.85)
    incident_med = sample_incident.model_copy(
        update={"max_confidence": 0.72, "attack_family": s.AttackFamily.BRUTE_FORCE, "verdict": s.Verdict.KNOWN_ATTACK}
    )
    brief_med = generate_template_brief(incident_med)
    assert brief_med.confidence_band == "medium"
    assert "Likely BruteForce" in brief_med.text
    assert "Recommended action" in brief_med.text

    # Low confidence (< 0.60)
    incident_low = sample_incident.model_copy(
        update={"max_confidence": 0.45, "attack_family": s.AttackFamily.BRUTE_FORCE, "verdict": s.Verdict.KNOWN_ATTACK}
    )
    brief_low = generate_template_brief(incident_low)
    assert brief_low.confidence_band == "low"
    assert "Possible BruteForce" in brief_low.text
    assert "Worth reviewing before escalating" in brief_low.text


def test_novel_anomaly_template_wording(sample_incident: s.IncidentDetail):
    """Novel anomaly template must explicitly state that no known attack family matched."""
    incident = sample_incident.model_copy(
        update={"verdict": s.Verdict.NOVEL_ANOMALY, "attack_family": s.AttackFamily.UNKNOWN, "max_confidence": 0.75}
    )
    brief = generate_template_brief(incident)
    assert "No known attack family matched" in brief.text
    assert "traffic sits far outside normal behaviour" in brief.text


def test_malicious_luflow_wording(sample_incident: s.IncidentDetail):
    """Malicious binary-only classification must state threat intelligence source and not guess an exploit family."""
    incident = sample_incident.model_copy(
        update={
            "verdict": s.Verdict.KNOWN_ATTACK,
            "attack_family": s.AttackFamily.MALICIOUS,
            "max_confidence": 0.90,
            "mitre_technique_id": None,
            "mitre_technique_name": None,
        }
    )
    brief = generate_template_brief(incident)
    assert "malicious per threat intelligence" in brief.text
    assert "unclassified exploit structure" in brief.text
    # Must not guess specific attack families
    for fam in ["Infiltration", "Botnet", "DDoS", "DoS", "BruteForce", "WebAttack"]:
        assert fam not in brief.text


def test_canonical_playbook_actions(sample_incident: s.IncidentDetail):
    """Every recognized attack family must map to its canonical next-step playbook action from docs/threat_model.md §7."""
    for family, expected_action in PLAYBOOK_ACTIONS.items():
        if family in (s.AttackFamily.BENIGN, s.AttackFamily.UNKNOWN):
            continue
        incident = sample_incident.model_copy(
            update={
                "attack_family": family,
                "verdict": s.Verdict.KNOWN_ATTACK,
                "max_confidence": 0.88,
            }
        )
        brief = generate_template_brief(incident)
        assert expected_action in brief.text


def test_format_feature_deviations_ratios():
    """Verify feature ratio formatting against baselines."""
    feats = [
        s.FeatureContribution(feature="flow_iat_mean", value=10.0, shap_value=0.25, baseline_median=40000.0),
        s.FeatureContribution(feature="syn_flag_count", value=5.0, shap_value=0.15, baseline_median=0.0),
    ]
    summary = format_feature_deviations(feats)
    assert "flow iat mean is ~4,000x lower than typical" in summary
    assert "syn flag count is elevated (5.0 vs normal 0)" in summary

    # Empty features
    assert "telemetry exhibited statistical deviation" in format_feature_deviations([])


def test_client_lazy_instantiation(monkeypatch):
    """Verify get_azure_openai_client handles missing vs set env vars."""
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    reset_client_cache()

    assert get_azure_openai_client() is None

    # When env vars are configured
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test-resource.openai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key-12345")
    reset_client_cache()

    client = get_azure_openai_client()
    assert client is not None
    # Verify singleton caching returns the same instance
    assert get_azure_openai_client() is client
