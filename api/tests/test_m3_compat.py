"""Regression tests found by running the API against the real M2 bundles (see docs/model_card.md §3):

* SHAP is capped per batch (it costs 10-100 ms/flow); an incident's SHAP mean must not be diluted by unexplained flows
* yet every incident touched by a batch gets at least one explained flow
* the drift monitor must persist its snapshot AFTER the scoring transaction commits (else: "database is locked")
* a Brief must satisfy the contract (`source` is "azure_openai" or "template")
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from api.app.correlator import _aggregate_top_features
from api.app.scoring import ScoringService
from api.app.services.drift import SNAPSHOT_INTERVAL, DriftMonitor
from api.tests.test_m3_04 import _make_flow_payload
from nscore.bundle.loader import load_bundle
from nscore.contracts import schemas
from nscore.contracts.schemas import FeatureContribution, Verdict
from scripts.init_db import init_db


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory):
    from scripts.make_mock_bundle import build

    return load_bundle(f"local:{build('cic', tmp_path_factory.mktemp('compat_bundle'), seed=7)}")


@pytest.fixture()
def conn(tmp_path: Path):
    from api.app.db import get_connection

    db = str(tmp_path / "compat.db")
    init_db(db)
    c = get_connection(db)
    yield c, db
    c.close()


def _one_pair(payload: dict) -> dict:
    """Every flow from the same source to the same destination, so incidents differ only by family."""
    for f in payload["flows"]:
        f["meta"]["src_ip"], f["meta"]["dst_ip"] = "10.9.9.9", "192.168.9.9"
    return payload


def test_shap_is_capped_per_batch_but_every_flow_is_scored(bundle, conn, monkeypatch):
    monkeypatch.setenv("NS_SHAP_MAX_PER_BATCH", "3")
    c, _ = conn
    payload = _one_pair(_make_flow_payload(bundle, n=80))
    result = ScoringService(bundle).score_batch(schemas.FlowBatch.model_validate(payload), c)
    attacks = [r for r in result.results if r.verdict is not Verdict.BENIGN]
    incidents = {r.incident_id for r in attacks}
    assert len(attacks) > max(3, len(incidents)), "precondition: more attack flows than the cap and the incidents"
    assert result.received == 80 and len(result.results) == 80
    assert sum(1 for r in attacks if r.top_features) <= max(3, len(incidents))
    # every attack flow still lands in an incident, and every incident got an explanation
    assert all(r.incident_id for r in attacks)
    assert all(any(r.top_features for r in attacks if r.incident_id == inc) for inc in incidents)


def test_every_incident_gets_an_explanation_even_when_its_flows_rank_below_the_cap(monkeypatch):
    """The bug: a novel-anomaly incident (risk 89 HIGH) had no SHAP; its flows were not in the top 25 by p_attack."""
    from datetime import UTC, datetime, timedelta
    from types import SimpleNamespace

    from api.app.scoring import _select_for_shap
    from nscore.contracts.schemas import AttackFamily

    t0 = datetime(2026, 10, 6, tzinfo=UTC)
    meta = [SimpleNamespace(src_ip=s, dst_ip="d", observed_at=t0) for s in ("a", "a", "a", "a", "b", "c", "c")]
    verdicts = [Verdict.KNOWN_ATTACK] * 4 + [Verdict.NOVEL_ANOMALY, Verdict.BENIGN, Verdict.KNOWN_ATTACK]
    families = [AttackFamily.DDOS] * 4 + [AttackFamily.UNKNOWN, AttackFamily.BENIGN, AttackFamily.DOS]
    p = [0.99, 0.98, 0.97, 0.96, 0.30, 0.01, 0.40]
    # cap 2: group a (best 0), novel group b (4) and group c (6) each get one; benign (5) never; no room for extras
    assert _select_for_shap(meta, verdicts, families, p, cap=2) == [0, 4, 6]
    # cap 5: the three representatives, then the most suspicious of the rest (1 and 2)
    assert _select_for_shap(meta, verdicts, families, p, cap=5) == [0, 1, 2, 4, 6]
    # cap 0 disables SHAP entirely
    assert _select_for_shap(meta, verdicts, families, p, cap=0) == []
    # the same key 10 minutes later is a separate incident (correlation window 5 min), so it gets its own explanation
    meta[3] = SimpleNamespace(src_ip="a", dst_ip="d", observed_at=t0 + timedelta(minutes=10))
    assert _select_for_shap(meta, verdicts, families, p, cap=2) == [0, 3, 4, 6]


def test_incidents_in_the_database_all_carry_top_features(bundle, conn, monkeypatch):
    monkeypatch.setenv("NS_SHAP_MAX_PER_BATCH", "2")
    c, _ = conn
    ScoringService(bundle).score_batch(schemas.FlowBatch.model_validate(_make_flow_payload(bundle, n=120)), c)
    rows = c.execute("SELECT incident_id, top_features_json FROM incidents").fetchall()
    assert len(rows) > 2, "precondition: more incidents than the cap"
    assert all(r["top_features_json"] not in (None, "", "[]") for r in rows)


def test_shap_cap_can_be_disabled_by_a_large_value(bundle, conn, monkeypatch):
    monkeypatch.setenv("NS_SHAP_MAX_PER_BATCH", "10000")
    c, _ = conn
    result = ScoringService(bundle).score_batch(schemas.FlowBatch.model_validate(_make_flow_payload(bundle, n=40)), c)
    attacks = [r for r in result.results if r.verdict is not Verdict.BENIGN]
    assert attacks and all(r.top_features for r in attacks)


def _contribution(value: float) -> FeatureContribution:
    return FeatureContribution(feature="f", value=1.0, shap_value=value, baseline_median=0.0)


def test_unexplained_flows_do_not_dilute_the_shap_mean():
    existing = '[{"feature": "f", "value": 1.0, "shap_value": 0.4, "baseline_median": 0.0}]'
    # a flow without SHAP leaves the mean exactly where it was
    assert _aggregate_top_features(existing, 2, [])[0]["shap_value"] == pytest.approx(0.4)
    # a flow with SHAP is averaged over the explained flows only: (2 * 0.4 + 1.0) / 3
    assert _aggregate_top_features(existing, 2, [_contribution(1.0)])[0]["shap_value"] == pytest.approx(0.6, abs=1e-4)
    # nothing explained yet and nothing new: empty, no division by zero
    assert _aggregate_top_features(None, 0, []) == []


def test_drift_snapshot_is_persisted_without_a_database_lock(bundle, conn, caplog):
    c, db = conn
    caplog.set_level(logging.WARNING)
    service, monitor = ScoringService(bundle), DriftMonitor(bundle, db)
    batch = schemas.FlowBatch.model_validate(_make_flow_payload(bundle, n=SNAPSHOT_INTERVAL))
    service.score_batch(batch, c, drift_monitor=monitor)
    assert "locked" not in caplog.text, caplog.text
    report = monitor.get_latest_report()
    assert report is not None
    # reference = the alert rate expected on normal traffic (the false-alarm budget), never a hard-coded 0
    assert report.reference_attack_rate == pytest.approx(bundle.thresholds["operating_fpr"])
    from api.app.db import get_connection

    check = get_connection(db)
    try:
        assert check.execute("SELECT COUNT(*) FROM drift_snapshots").fetchone()[0] >= 1
    finally:
        check.close()


def test_brief_source_satisfies_the_contract():
    import asyncio

    from api.app.services.brief import generate_and_cache_brief

    class Repo:
        def update_incident_brief(self, *_):
            pass

    brief = asyncio.run(generate_and_cache_brief("inc-1", {"risk_level": "HIGH"}, Repo(), timeout=2.0))
    schemas.Brief.model_validate(brief.model_dump())  # raises if `source` is not an allowed literal
    assert brief.source in ("azure_openai", "template")


def test_keys_fail_closed_when_not_configured(monkeypatch):
    """No NS_API_KEY / NS_ADMIN_KEY on the server: refuse, never accept a well-known default."""
    from fastapi.testclient import TestClient

    from api.app.main import app
    from api.tests.helpers import one_flow_batch

    monkeypatch.setenv("NS_MOCK", "1")
    monkeypatch.delenv("NS_API_KEY")
    monkeypatch.delenv("NS_ADMIN_KEY")
    c = TestClient(app)
    old_defaults = {"x-api-key": "test_api_key", "x-admin-key": "admin_secret"}
    assert c.post("/v1/flows", json=one_flow_batch(), headers=old_defaults).status_code == 503
    assert c.post("/v1/admin/reload-model", json={"model_ref": "local:x"}, headers=old_defaults).status_code == 503
