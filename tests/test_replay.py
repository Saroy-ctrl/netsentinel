"""Unit tests for the NetSentinel Replay Engine (M5-05).

Tests scenario loading, CSV flow batching, mock scoring, pacing logic,
and ground-truth metrics tracking without requiring a live FastAPI server.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nscore.contracts.schemas import AttackFamily, FlowBatch, FlowRecord, Verdict
from replay.replay import (
    ReplayEngine,
    load_flow_records,
    load_scenario,
    mock_score_batch,
    run_replay,
)

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_DIR = ROOT / "replay" / "scenarios"
SAMPLES_DIR = ROOT / "replay" / "samples"


def test_load_all_scenarios():
    """Verify all 5 demo scenario YAMLs are present and parse correctly."""
    scenario_files = list(SCENARIOS_DIR.glob("*.yaml"))
    assert len(scenario_files) >= 5

    for sf in scenario_files:
        scen = load_scenario(sf)
        assert "name" in scen
        assert "file" in scen
        assert "bundle" in scen
        assert "speed" in scen
        assert "batch_size" in scen
        assert 1 <= scen["batch_size"] <= 500


def test_load_flow_records_from_sample():
    """Verify loading flows from real replay CSV sample into FlowRecord contracts."""
    sample_file = SAMPLES_DIR / "2018_benign_background.csv.gz"
    records, times = load_flow_records(sample_file, max_flows=50)

    assert len(records) == 50
    assert len(times) == 50
    for rec in records:
        assert isinstance(rec, FlowRecord)
        assert rec.meta.src_ip is not None
        assert rec.meta.dst_ip is not None
        assert rec.features["protocol"] == float(rec.meta.protocol)
        assert rec.ground_truth == "BENIGN"


def test_mock_score_batch_verdicts():
    """Verify mock scoring behavior across benign, known attack, and holdout novel cases."""
    # Benign flows
    sample_benign = SAMPLES_DIR / "2018_benign_background.csv.gz"
    b_recs, _ = load_flow_records(sample_benign, max_flows=10)
    resp_b = mock_score_batch(FlowBatch(flows=b_recs), bundle="cic-v1")
    assert resp_b.received == 10
    assert all(r.verdict == Verdict.BENIGN for r in resp_b.results)

    # Known attack flows (Brute Force)
    sample_attack = SAMPLES_DIR / "2018_ssh_bruteforce.csv.gz"
    a_recs, _ = load_flow_records(sample_attack, max_flows=10)
    resp_a = mock_score_batch(FlowBatch(flows=a_recs), bundle="cic-v1")
    assert resp_a.received == 10
    assert all(r.verdict == Verdict.KNOWN_ATTACK for r in resp_a.results)
    assert all(r.attack_family == AttackFamily.BRUTE_FORCE for r in resp_a.results)

    # Novel anomaly case (Ares botnet against holdout bundle)
    sample_botnet = SAMPLES_DIR / "2018_botnet_ares.csv.gz"
    bot_recs, _ = load_flow_records(sample_botnet, max_flows=10)
    resp_novel = mock_score_batch(FlowBatch(flows=bot_recs), bundle="cic-holdout-botnet")
    assert resp_novel.received == 10
    assert all(r.verdict == Verdict.NOVEL_ANOMALY for r in resp_novel.results)
    assert all(r.attack_family == AttackFamily.UNKNOWN for r in resp_novel.results)
    assert all(r.closest_family is not None for r in resp_novel.results)


def test_replay_engine_mock_run():
    """Test ReplayEngine execution and metrics tracking."""
    sample_file = SAMPLES_DIR / "2018_ssh_bruteforce.csv.gz"
    records, times = load_flow_records(sample_file, max_flows=60)

    engine = ReplayEngine(
        flows=records,
        times=times,
        speed=0.0,  # instant
        batch_size=25,
        scenario_name="test_run",
        file_path=str(sample_file),
        bundle="cic-v1",
        mock=True,
        verbose=False,
    )

    summary = engine.run()
    assert summary.total_flows == 60
    assert summary.batches_sent == 3  # 25 + 25 + 10
    assert summary.detected_known == 60
    assert summary.true_positives == 60
    assert summary.false_positives == 0
    assert summary.precision == 1.0
    assert summary.recall == 1.0
    assert summary.f1 == 1.0


def test_run_replay_by_scenario_name():
    """Verify run_replay resolves scenarios by name and runs cleanly."""
    summary = run_replay(
        scenario="act1_calm",
        max_flows=40,
        speed=0.0,
        batch_size=20,
        mock=True,
        verbose=False,
    )

    assert summary.scenario == "act1_calm"
    assert summary.total_flows == 40
    assert summary.batches_sent == 2
    assert summary.detected_benign == 40


# --- regression: the replay used to substitute ground-truth-derived "results" whenever the API failed -----------------

def _engine(**kw):
    from replay.replay import ReplayEngine, load_flow_records

    flows, times = load_flow_records(SAMPLES_DIR / "2018_botnet_ares.csv.gz", max_flows=20)
    return ReplayEngine(flows=flows, times=times, speed=0, batch_size=10, verbose=False, **kw)


def test_api_failure_raises_instead_of_simulating():

    from replay.replay import ReplayError

    eng = _engine(api_url="http://127.0.0.1:9", bundle="cic-holdout-botnet")  # nothing listens on port 9
    with pytest.raises(ReplayError, match="not reachable|No results were simulated"):
        eng.run()


def test_rejected_key_explains_the_fix(monkeypatch):
    import httpx

    from replay.replay import ReplayEngine, ReplayError

    def forbidden(self, batch):
        req = httpx.Request("POST", "http://api/v1/flows")
        raise httpx.HTTPStatusError("403", request=req, response=httpx.Response(403, request=req))

    monkeypatch.setattr(ReplayEngine, "_send_batch_http", forbidden)
    eng = _engine()
    with pytest.raises(ReplayError, match="NS_API_KEY"):
        eng.send_batch(None)


def test_wrong_model_stops_or_switches(monkeypatch):
    import httpx

    from replay.replay import ReplayError

    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(200, json={"model_version": "cic-v1-20261002"}))
    with pytest.raises(ReplayError, match="cic-holdout-botnet"):
        _engine(bundle="cic-holdout-botnet").ensure_bundle()

    calls = {}

    def reload(url, json, headers, timeout):
        calls.update(url=url, json=json, headers=headers)
        return httpx.Response(200, json={"model_version": "cic-holdout-botnet-20261002"})

    monkeypatch.setattr(httpx, "post", reload)
    assert _engine(bundle="cic-holdout-botnet", admin_key="a").ensure_bundle().startswith("cic-holdout-botnet")
    assert calls["json"] == {"model_ref": "local:artifacts/bundles/cic-holdout-botnet"}
    assert calls["headers"] == {"X-Admin-Key": "a"}


def test_simulated_runs_are_labelled(capsys):
    eng = _engine(mock=True, bundle="cic-holdout-botnet")
    eng.verbose = True
    eng.run()
    assert "SIMULATED" in capsys.readouterr().out
