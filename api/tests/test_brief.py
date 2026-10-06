"""Unit tests for incident brief service (M5-03).

Tests LLM brief generation with a stubbed Azure OpenAI client,
deterministic template fallback, 8-second timeout handling,
confidence-band hedging, novel-anomaly wording, and contract validation.
"""

from __future__ import annotations

import asyncio
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
    generate_and_cache_brief,
    generate_brief,
    generate_template_brief,
    get_azure_openai_client,
    incident_data_to_incident_detail,
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


# --------------------------------------------------------------------------- M3 Wrapper Tests


class MockRepo:
    """Mock repository mimicking M3 Repository.update_incident_brief."""

    def __init__(self, should_fail: bool = False):
        self.calls: list[tuple[str, str]] = []
        self.should_fail = should_fail

    def update_incident_brief(self, incident_id: str, brief_json: str):
        if self.should_fail:
            raise RuntimeError("Database persistence failure")
        self.calls.append((incident_id, brief_json))


def test_generate_and_cache_brief_m3_call():
    """Verify that calling generate_and_cache_brief with M3 row dict produces a valid Brief and persists it."""
    incident_data = {
        "status": "new",
        "verdict": "known_attack",
        "attack_family": "DoS",
        "mitre_id": "T1498",
        "mitre_name": "Network Denial of Service",
        "risk_score": 75,
        "risk_level": "HIGH",
        "severity": 0.8,
        "max_confidence": 0.92,
        "flow_count": 500,
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "top_features_json": json.dumps([
            {"feature": "flow_duration", "value": 10.0, "shap_value": 0.35, "baseline_median": 500.0}
        ]),
    }
    repo = MockRepo()
    brief = asyncio.run(generate_and_cache_brief("inc-m3-01", incident_data, repo=repo))

    assert isinstance(brief, s.Brief)
    assert brief.incident_id == "inc-m3-01"
    assert brief.source == "template"
    assert brief.confidence_band == "high"
    assert "192.168.1.10" in brief.text
    assert "DoS" in brief.text

    # Verify repository persistence
    assert len(repo.calls) == 1
    assert repo.calls[0][0] == "inc-m3-01"
    saved = s.Brief.model_validate(json.loads(repo.calls[0][1]))
    assert saved.incident_id == brief.incident_id
    assert saved.text == brief.text


def test_generate_and_cache_brief_cached_path():
    """Verify that when refresh=False and a valid cached brief exists, it is returned without re-generation."""
    cached_brief = s.Brief(
        incident_id="inc-cached",
        text="Previously cached brief text for incident.",
        source="template",
        confidence_band="high",
        generated_at=datetime.now(timezone.utc),
    )
    repo = MockRepo()

    # Case A: cached via brief_json
    incident_data_a = {"brief_json": cached_brief.model_dump_json()}
    result_a = asyncio.run(generate_and_cache_brief("inc-cached", incident_data_a, repo=repo, refresh=False))
    assert result_a == cached_brief
    assert len(repo.calls) == 0  # Not re-persisted

    # Case B: cached via brief object
    incident_data_b = {"brief": cached_brief}
    result_b = asyncio.run(generate_and_cache_brief("inc-cached", incident_data_b, repo=repo, refresh=False))
    assert result_b == cached_brief
    assert len(repo.calls) == 0


def test_generate_and_cache_brief_refresh_path():
    """Verify that when refresh=True, cached brief is bypassed and a new brief is generated and persisted."""
    cached_brief = s.Brief(
        incident_id="inc-refreshed",
        text="Old cached brief text.",
        source="template",
        confidence_band="low",
        generated_at=datetime.now(timezone.utc),
    )
    incident_data = {
        "attack_family": "Infiltration",
        "max_confidence": 0.88,
        "src_ip": "10.0.1.50",
        "dst_port": 22,
        "brief_json": cached_brief.model_dump_json(),
    }
    repo = MockRepo()
    brief = asyncio.run(generate_and_cache_brief("inc-refreshed", incident_data, repo=repo, refresh=True))

    assert brief.text != cached_brief.text
    assert "Infiltration" in brief.text
    assert len(repo.calls) == 1
    assert repo.calls[0][0] == "inc-refreshed"


def test_generate_and_cache_brief_repo_persistence():
    """Verify persistence handles None repo, non-persisting repo, failing repo, and async repo without crashing."""
    incident_data = {"attack_family": "Botnet", "max_confidence": 0.90}

    # None repo
    brief_none = asyncio.run(generate_and_cache_brief("inc-p1", incident_data, repo=None))
    assert isinstance(brief_none, s.Brief)

    # Repo lacking update_incident_brief
    brief_empty = asyncio.run(generate_and_cache_brief("inc-p2", incident_data, repo=object()))
    assert isinstance(brief_empty, s.Brief)

    # Repo that raises an error (should warn but not crash)
    failing_repo = MockRepo(should_fail=True)
    brief_fail = asyncio.run(generate_and_cache_brief("inc-p3", incident_data, repo=failing_repo))
    assert isinstance(brief_fail, s.Brief)

    # Async repo
    class AsyncRepo:
        def __init__(self):
            self.calls: list[tuple[str, str]] = []

        async def update_incident_brief(self, i_id: str, b_json: str):
            self.calls.append((i_id, b_json))

    async_repo = AsyncRepo()
    brief_async = asyncio.run(generate_and_cache_brief("inc-p4", incident_data, repo=async_repo))
    assert isinstance(brief_async, s.Brief)
    assert len(async_repo.calls) == 1


def test_generate_and_cache_brief_with_stubbed_client():
    """Verify that Azure/stubbed generation through wrapper sets source='azure_openai' and calls client."""
    mock_client = _make_mock_client(return_text="Stubbed Azure brief through M3 wrapper.")
    incident_data = {
        "attack_family": "Botnet",
        "max_confidence": 0.95,
        "src_ip": "172.16.0.4",
        "dst_port": 8080,
    }
    repo = MockRepo()
    brief = asyncio.run(
        generate_and_cache_brief(
            "inc-stub",
            incident_data,
            repo=repo,
            refresh=True,
            client=mock_client,
        )
    )

    assert brief.source == "azure_openai"
    assert brief.model_deployment == DEFAULT_DEPLOYMENT
    assert brief.text == "Stubbed Azure brief through M3 wrapper."
    assert len(repo.calls) == 1


def test_generate_and_cache_brief_timeout_fallback():
    """Verify that timeout triggered via _test_timeout or slow execution falls back to template."""
    incident_data = {"risk_level": "CRITICAL", "_test_timeout": True}
    repo = MockRepo()
    brief = asyncio.run(
        generate_and_cache_brief(
            "inc-timeout",
            incident_data,
            repo=repo,
            timeout=0.05,
        )
    )

    assert brief.source == "template"
    assert "Fallback" in brief.text or "Timeout" in brief.text
    assert brief.confidence_band == "low"
    assert len(repo.calls) == 1


def test_generate_and_cache_brief_m3_wording_constraints():
    """Verify backward compatibility with M3 wording constraint expectations."""
    incident_data = {"attack_family": "novel_anomaly", "verdict": "Malicious", "_test_timeout": False}
    repo = MockRepo()
    brief = asyncio.run(
        generate_and_cache_brief(
            "inc-wording",
            incident_data,
            repo=repo,
            timeout=2.0,
        )
    )

    assert brief.source in ("template", "azure_openai")
    assert "novel_anomaly" in brief.text
    assert "Malicious" in brief.text
    assert len(repo.calls) == 1
