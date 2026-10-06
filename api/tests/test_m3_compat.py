"""Regression tests found by running the API against the real M2 bundles (see docs/model_card.md §3):

* SHAP is capped per batch (it costs 10-100 ms/flow); an incident's SHAP mean must not be diluted by unexplained flows
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


def test_shap_is_capped_per_batch_but_every_flow_is_scored(bundle, conn, monkeypatch):
    monkeypatch.setenv("NS_SHAP_MAX_PER_BATCH", "3")
    c, _ = conn
    result = ScoringService(bundle).score_batch(schemas.FlowBatch.model_validate(_make_flow_payload(bundle, n=80)), c)
    attacks = [r for r in result.results if r.verdict is not Verdict.BENIGN]
    assert len(attacks) > 3, "precondition: the batch must contain more attack flows than the cap"
    assert result.received == 80 and len(result.results) == 80
    assert sum(1 for r in attacks if r.top_features) <= 3
    # explained flows are the most suspicious ones
    explained = [r.p_attack for r in attacks if r.top_features]
    unexplained = [r.p_attack for r in attacks if not r.top_features]
    assert min(explained) >= max(unexplained)
    # every attack flow still lands in an incident
    assert all(r.incident_id for r in attacks)


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
    assert monitor.get_latest_report() is not None
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
