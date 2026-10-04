"""M3-06 tests: Risk and MITRE enrichment.

Tests expected severity calculations (including probability-weighted),
MITRE ATT&CK mapping for all attack families, team worked examples,
novelty bonus, burst scaling, and end-to-end database recomputation on upsert.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app.correlator import IncidentCorrelator
from nscore.bundle.loader import load_bundle
from nscore.contracts import policy
from nscore.contracts.schemas import AttackFamily, FlowMeta, Verdict

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def mock_bundle_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from scripts.make_mock_bundle import build

    out_root = tmp_path_factory.mktemp("bundles_m306")
    return build("cic", out_root, seed=42)


@pytest.fixture(scope="session")
def real_bundle(mock_bundle_path: Path):
    return load_bundle(f"local:{mock_bundle_path}")


@pytest.fixture()
def db_conn(tmp_path: Path):
    """Isolated SQLite connection for unit-level tests."""
    from scripts.init_db import init_db

    p = str(tmp_path / "m306_unit.db")
    init_db(p)
    conn = sqlite3.connect(p)
    conn.execute("PRAGMA foreign_keys = ON;")
    yield conn
    conn.close()


@pytest.fixture()
def scoring_client(real_bundle, tmp_path: Path):
    """TestClient with real bundle and isolated DB injected."""
    from api.app.main import app
    from api.app.scoring import ScoringService
    from scripts.init_db import init_db

    db_file = str(tmp_path / "m306_api.db")
    init_db(db_file)

    prior_bundle = getattr(app.state, "bundle", None)
    prior_scorer = getattr(app.state, "scorer", None)

    app.state.bundle = real_bundle
    app.state.scorer = ScoringService(real_bundle)

    prev_db = os.environ.get("NS_DB_PATH")
    os.environ["NS_DB_PATH"] = db_file

    client = TestClient(app, raise_server_exceptions=True)
    yield client, db_file

    app.state.bundle = prior_bundle
    app.state.scorer = prior_scorer
    if prev_db is not None:
        os.environ["NS_DB_PATH"] = prev_db
    else:
        os.environ.pop("NS_DB_PATH", None)


def _make_meta(
    flow_id: str = "f-1",
    observed_at: str = "2026-10-04T12:00:00Z",
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    src_port: int = 50000,
    dst_port: int = 80,
    protocol: int = 6,
) -> FlowMeta:
    return FlowMeta(
        flow_id=flow_id,
        observed_at=datetime.fromisoformat(observed_at.replace("Z", "+00:00")),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
    )


# ---------------------------------------------------------------------------
# 1. Expected Severity Tests
# ---------------------------------------------------------------------------

class TestExpectedSeverity:
    """Verifies severity policy weights and probability-weighted math."""

    def test_all_individual_family_weights(self):
        """Matches docs/03_architecture.md §4.4 severity table exactly."""
        expected = {
            AttackFamily.INFILTRATION: 1.00,
            AttackFamily.BOTNET: 0.90,
            AttackFamily.DDOS: 0.80,
            AttackFamily.DOS: 0.80,
            AttackFamily.RARE: 0.80,
            AttackFamily.UNKNOWN: 0.75,
            AttackFamily.BRUTE_FORCE: 0.70,
            AttackFamily.MALICIOUS: 0.70,
            AttackFamily.WEB_ATTACK: 0.60,
            AttackFamily.PORTSCAN: 0.30,
            AttackFamily.BENIGN: 0.00,
        }
        for fam, weight in expected.items():
            assert policy.expected_severity(fam) == weight, f"Weight mismatch for {fam}"

    def test_probability_weighted_severity(self):
        """Σ P(f|attack) * W[f] over multiclass family head probabilities."""
        # 50/50 split between WebAttack (0.6) and Infiltration (1.0) -> 0.8
        probs = {AttackFamily.WEB_ATTACK: 0.5, AttackFamily.INFILTRATION: 0.5}
        sev = policy.expected_severity(AttackFamily.WEB_ATTACK, probs)
        assert pytest.approx(sev, rel=1e-5) == 0.80

        # 70% DoS (0.8) + 30% BruteForce (0.7) -> 0.56 + 0.21 = 0.77
        probs2 = {AttackFamily.DOS: 0.7, AttackFamily.BRUTE_FORCE: 0.3}
        sev2 = policy.expected_severity(AttackFamily.DOS, probs2)
        assert pytest.approx(sev2, rel=1e-5) == 0.77

    def test_binary_only_bundle_malicious_fallback(self):
        """Binary-only LUFlow bundle uses W[Malicious] = 0.70 without family probs."""
        assert policy.expected_severity(AttackFamily.MALICIOUS) == 0.70

    def test_novel_anomaly_unknown_fallback(self):
        """Novel anomalies evaluate to W[Unknown] = 0.75."""
        assert policy.expected_severity(AttackFamily.UNKNOWN) == 0.75


# ---------------------------------------------------------------------------
# 2. MITRE ATT&CK Mapping Tests
# ---------------------------------------------------------------------------

class TestMitreMapping:
    """Verifies MITRE technique IDs and names across all attack families."""

    def test_supported_mitre_families(self):
        assert policy.mitre_for(AttackFamily.BRUTE_FORCE) == ("T1110", "Brute Force")
        assert policy.mitre_for(AttackFamily.DOS) == ("T1499", "Endpoint Denial of Service")
        assert policy.mitre_for(AttackFamily.DDOS) == ("T1498", "Network Denial of Service")
        assert policy.mitre_for(AttackFamily.WEB_ATTACK) == ("T1190", "Exploit Public-Facing Application")
        assert policy.mitre_for(AttackFamily.INFILTRATION) == (
            "T1046",
            "Network Service Discovery (internal, post-compromise)",
        )
        assert policy.mitre_for(AttackFamily.BOTNET) == ("T1071", "Application Layer Protocol (C2)")
        assert policy.mitre_for(AttackFamily.PORTSCAN) == ("T1046", "Network Service Discovery")

    def test_unmapped_families_return_none(self):
        """Novel, binary-only, rare, and benign have no specific static technique."""
        assert policy.mitre_for(AttackFamily.UNKNOWN) == (None, None)
        assert policy.mitre_for(AttackFamily.MALICIOUS) == (None, None)
        assert policy.mitre_for(AttackFamily.RARE) == (None, None)
        assert policy.mitre_for(AttackFamily.BENIGN) == (None, None)

    def test_string_lookup_equivalence(self):
        """mitre_for works with string representation as well as AttackFamily enum."""
        assert policy.mitre_for("DoS") == ("T1499", "Endpoint Denial of Service")
        assert policy.mitre_for("BruteForce") == ("T1110", "Brute Force")


# ---------------------------------------------------------------------------
# 3. Risk Engine Tests
# ---------------------------------------------------------------------------

class TestRiskEngine:
    """Verifies team worked examples, burst multiplier, and novelty bonus."""

    def test_team_worked_examples(self):
        """Verifies reference examples: BruteForce 62, Infiltration 81, PortScan 28."""
        k = Verdict.KNOWN_ATTACK
        # BruteForce: conf=0.88, sev=0.70, burst=1.00 -> 0.88 * 0.70 * 100 = 61.6 -> 62 (MEDIUM)
        assert policy.risk_score(k, 0.88, policy.expected_severity(AttackFamily.BRUTE_FORCE)) == 62
        assert policy.risk_level(62) == "MEDIUM"

        # Infiltration: conf=0.81, sev=1.00, burst=1.00 -> 0.81 * 1.00 * 100 = 81.0 -> 81 (HIGH)
        assert policy.risk_score(k, 0.81, policy.expected_severity(AttackFamily.INFILTRATION)) == 81
        assert policy.risk_level(81) == "HIGH"

        # PortScan: conf=0.95, sev=0.30, burst=1.00 -> 0.95 * 0.30 * 100 = 28.5 -> 28 (LOW)
        assert policy.risk_score(k, 0.95, policy.expected_severity(AttackFamily.PORTSCAN)) == 28
        assert policy.risk_level(28) == "LOW"

    def test_novelty_bonus_applied_only_to_novel(self):
        """NOVEL_ANOMALY gets exactly +10 points bonus."""
        conf = 0.60
        sev = 0.75
        # Known: 0.60 * 0.75 = 0.45 -> 45
        assert policy.risk_score(Verdict.KNOWN_ATTACK, conf, sev, flow_count=1) == 45
        # Novel: 0.60 * 0.75 + 0.10 = 0.55 -> 55
        assert policy.risk_score(Verdict.NOVEL_ANOMALY, conf, sev, flow_count=1) == 55

    def test_benign_verdict_always_zero_risk(self):
        assert policy.risk_score(Verdict.BENIGN, 0.99, 1.0, flow_count=100) == 0

    def test_burst_factor_scaling(self):
        """1 flow -> 1.00; 1000 flows -> 1.15; caps at 1.15."""
        assert policy.burst_factor(1) == 1.00
        assert pytest.approx(policy.burst_factor(10), rel=1e-5) == 1.05
        assert pytest.approx(policy.burst_factor(100), rel=1e-5) == 1.10
        assert pytest.approx(policy.burst_factor(1000), rel=1e-5) == 1.15
        assert pytest.approx(policy.burst_factor(10000), rel=1e-5) == 1.15

    def test_risk_level_boundaries(self):
        assert policy.risk_level(39) == "LOW"
        assert policy.risk_level(40) == "MEDIUM"
        assert policy.risk_level(69) == "MEDIUM"
        assert policy.risk_level(70) == "HIGH"


# ---------------------------------------------------------------------------
# 4. Database Enrichment & Recomputation on Upsert
# ---------------------------------------------------------------------------

class TestEnrichmentOnUpsert:
    """Verifies that MITRE and Risk enrichment are stored and re-enriched on upsert."""

    def test_mitre_and_risk_populated_on_insert(self, db_conn):
        correlator = IncidentCorrelator()
        t = "2026-10-04T12:00:00Z"

        inc_id, c, u = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.BOTNET,
            confidence=0.85,
            severity=0.90,
            model_version="v1",
            top_features=[],
        )
        assert c == 1 and u == 0

        row = db_conn.execute(
            """SELECT mitre_id, mitre_name, risk_score, risk_level, severity, max_confidence
               FROM incidents WHERE incident_id = ?""",
            (inc_id,),
        ).fetchone()

        assert row[0] == "T1071"
        assert row[1] == "Application Layer Protocol (C2)"
        # 0.85 * 0.90 * 1.00 * 100 = 76.5 -> 76 (HIGH)
        assert row[2] == 76
        assert row[3] == "HIGH"
        assert pytest.approx(row[4], rel=1e-5) == 0.90
        assert pytest.approx(row[5], rel=1e-5) == 0.85

    def test_mitre_and_risk_recomputed_on_upsert(self, db_conn):
        correlator = IncidentCorrelator()
        t0 = "2026-10-04T12:00:00Z"
        t1 = "2026-10-04T12:02:00Z"

        inc_id, _, _ = correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f1", t0),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.70,
            severity=0.80,
            model_version="v1",
            top_features=[],
        )

        # Merge second flow: higher confidence (0.95), lower severity (0.60)
        correlator.correlate_flow(
            conn=db_conn,
            meta=_make_meta("f2", t1),
            verdict=Verdict.KNOWN_ATTACK,
            family=AttackFamily.DOS,
            confidence=0.95,
            severity=0.60,
            model_version="v1",
            top_features=[],
        )

        row = db_conn.execute(
            """SELECT mitre_id, mitre_name, severity, max_confidence, flow_count, risk_score, risk_level
               FROM incidents WHERE incident_id = ?""",
            (inc_id,),
        ).fetchone()

        assert row[0] == "T1499"
        assert row[1] == "Endpoint Denial of Service"
        # Running severity: (0.80 + 0.60) / 2 = 0.70
        assert pytest.approx(row[2], rel=1e-5) == 0.70
        # Max confidence: max(0.70, 0.95) = 0.95
        assert pytest.approx(row[3], rel=1e-5) == 0.95
        assert row[4] == 2

        # Risk recomputed for flow_count=2:
        # burst = 1 + 0.15 * log10(2)/3 = 1 + 0.15 * 0.10034 = 1.01505
        # raw = 0.95 * 0.70 * 1.01505 = 0.6750 -> 68 (MEDIUM)
        expected_risk = policy.risk_score(Verdict.KNOWN_ATTACK, 0.95, 0.70, flow_count=2)
        assert row[5] == expected_risk
        assert row[6] == policy.risk_level(expected_risk)

    def test_flow_level_severity_persisted_in_flows_table(self, scoring_client, real_bundle):
        """Verifies that individual flow expected severity is saved in the flows table."""
        client, db_file = scoring_client
        import numpy as np

        from scripts.make_mock_bundle import synthetic_frame

        rng = np.random.default_rng(123)
        df, _, _ = synthetic_frame(real_bundle.spec, rng)
        row = df.iloc[0]
        features = {name: float(row[name]) for name in real_bundle.spec.names}

        payload = {
            "flows": [{
                "meta": {
                    "flow_id": "flow-m306-001",
                    "observed_at": "2026-10-04T12:00:00Z",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "192.168.1.1",
                    "src_port": 54321,
                    "dst_port": 80,
                    "protocol": 6,
                },
                "features": features,
            }]
        }

        resp = client.post("/v1/flows", json=payload)
        assert resp.status_code == 200

        conn = sqlite3.connect(db_file)
        flow_row = conn.execute(
            "SELECT severity, verdict, attack_family, incident_id FROM flows WHERE flow_id = 'flow-m306-001'"
        ).fetchone()
        conn.close()

        assert flow_row is not None
        # Flow severity must be a float between 0 and 1
        assert 0.0 <= flow_row[0] <= 1.0
