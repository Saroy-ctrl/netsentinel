"""M3-04: Scoring service for POST /v1/flows.

Encapsulates the full per-batch scoring pipeline so it can be tested
independently from the FastAPI routing layer:

    FlowBatch
      → spec validation (422 on missing features)
      → FlowTransformer.transform_records          (DetectionEngine.detect)
      → RF binary + optional family head
      → fuse()                                     (engine handles this)
      → SHAP top-5 for non-benign flows            (graceful degradation if shap unavailable)
      → persist: flows table + minimal incident rows
      → return ScoreBatchResponse

Architecture references: docs/03_architecture.md §4.2, §4.5
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import UTC, datetime

from nscore.bundle.loader import Bundle
from nscore.contracts import policy, schemas
from nscore.contracts.schemas import AttackFamily, Verdict
from nscore.detection.engine import DetectionEngine

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _try_build_explainer(bundle: Bundle):
    """Build an Explainer, returning None if shap is unavailable."""
    try:
        from nscore.detection.explain import Explainer
        return Explainer(bundle)
    except Exception as exc:
        logger.warning("M3-04: SHAP explainer unavailable, top_features will be empty. Error: %s", exc)
        return None


class ScoringService:
    """Stateless (after construction) scoring pipeline for one bundle.

    Constructed once per loaded bundle (in the lifespan), re-used for every
    POST /v1/flows request.
    """

    def __init__(self, bundle: Bundle) -> None:
        self.bundle = bundle
        self.engine = DetectionEngine(bundle)
        self.explainer = _try_build_explainer(bundle)
        self.model_version = bundle.version

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_batch(
        self,
        batch: schemas.FlowBatch,
        conn,  # sqlite3.Connection from db_session
    ) -> schemas.ScoreBatchResponse:
        """Score a FlowBatch, persist to DB, return ScoreBatchResponse."""
        flow_records = batch.flows

        # Build feature dicts for the engine (transform_records expects list[dict])
        feature_dicts = [fr.features for fr in flow_records]

        # ----------------------------------------------------------------
        # Transform + detect  (raises MissingFeaturesError → 422 upstream)
        # ----------------------------------------------------------------
        t0 = time.perf_counter()
        det = self.engine.detect(feature_dicts)
        batch_latency_ms = (time.perf_counter() - t0) * 1000
        per_flow_latency_ms = batch_latency_ms / len(flow_records)

        # ----------------------------------------------------------------
        # SHAP for non-benign flows (best-effort)
        # ----------------------------------------------------------------
        non_benign_idx = [
            i for i, v in enumerate(det.verdict) if v is not Verdict.BENIGN
        ]
        contributions: list[list[schemas.FeatureContribution]] = [
            [] for _ in flow_records
        ]
        if self.explainer is not None and non_benign_idx and det.raw is not None:
            try:
                nb_X = det.X[non_benign_idx]
                nb_raw = det.raw[non_benign_idx]
                nb_contribs = self.explainer.contributions(nb_X, nb_raw, k=5, fast=True)
                for list_pos, flow_idx in enumerate(non_benign_idx):
                    contributions[flow_idx] = nb_contribs[list_pos]
            except Exception as exc:
                logger.warning("M3-04: SHAP contribution failed: %s", exc)

        # ----------------------------------------------------------------
        # Persist flows + minimal incidents; build response
        # ----------------------------------------------------------------
        results: list[schemas.ScoreResult] = []
        incidents_created = 0
        incidents_updated = 0

        for i, flow_record in enumerate(flow_records):
            meta = flow_record.meta
            v = det.verdict[i]
            fam = det.family[i]
            conf = float(det.confidence[i])
            p_atk = float(det.p_attack[i])
            anm_pct = float(det.anomaly_percentile[i])

            # Family confidence — None for benign/binary-only bundles
            raw_fconf = det.family_confidence[i]
            import math
            fconf: float | None = None if math.isnan(raw_fconf) else float(raw_fconf)
            closest: AttackFamily | None = det.closest_family[i]

            # Expected severity using final-arch formula
            fprobs = det.family_probs[i]
            sev = policy.expected_severity(fam, fprobs) if v is not Verdict.BENIGN else 0.0

            incident_id: str | None = None

            if v is not Verdict.BENIGN:
                # Minimal incident stub for M3-04 (full correlator in M3-05)
                incident_id, inc_created, inc_updated = _upsert_minimal_incident(
                    conn=conn,
                    meta=meta,
                    verdict=v,
                    family=fam,
                    confidence=conf,
                    severity=sev,
                    model_version=self.model_version,
                    top_features=contributions[i],
                )
                incidents_created += inc_created
                incidents_updated += inc_updated

            # Persist flow row
            _persist_flow(
                conn=conn,
                meta=meta,
                verdict=v,
                p_attack=p_atk,
                anomaly_pct=anm_pct,
                family=fam,
                severity=sev,
                incident_id=incident_id,
                ground_truth=flow_record.ground_truth,
                model_version=self.model_version,
                latency_ms=per_flow_latency_ms,
                features=flow_record.features,
            )

            results.append(
                schemas.ScoreResult(
                    flow_id=meta.flow_id,
                    verdict=v,
                    p_attack=p_atk,
                    anomaly_percentile=min(anm_pct, 100.0),
                    attack_family=fam,
                    family_confidence=fconf,
                    closest_family=closest,
                    top_features=contributions[i],
                    incident_id=incident_id,
                    model_version=self.model_version,
                    latency_ms=per_flow_latency_ms,
                )
            )

        conn.commit()

        return schemas.ScoreBatchResponse(
            received=len(flow_records),
            results=results,
            incidents_created=incidents_created,
            incidents_updated=incidents_updated,
        )


# ---------------------------------------------------------------------------
# DB persistence helpers
# ---------------------------------------------------------------------------


def _persist_flow(
    *,
    conn,
    meta: schemas.FlowMeta,
    verdict: Verdict,
    p_attack: float,
    anomaly_pct: float,
    family: AttackFamily,
    severity: float,
    incident_id: str | None,
    ground_truth: str | None,
    model_version: str,
    latency_ms: float,
    features: dict[str, float],
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO flows (
            flow_id, observed_at, received_at,
            src_ip, dst_ip, src_port, dst_port, protocol,
            features_json, verdict, p_attack, anomaly_pct,
            attack_family, severity, incident_id,
            ground_truth, model_version, latency_ms
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            meta.flow_id,
            meta.observed_at.isoformat(),
            _now_iso(),
            meta.src_ip,
            meta.dst_ip,
            meta.src_port,
            meta.dst_port,
            meta.protocol,
            json.dumps(features),
            verdict.value,
            p_attack,
            anomaly_pct,
            family.value,
            severity,
            incident_id,
            ground_truth,
            model_version,
            latency_ms,
        ),
    )


def _upsert_minimal_incident(
    *,
    conn,
    meta: schemas.FlowMeta,
    verdict: Verdict,
    family: AttackFamily,
    confidence: float,
    severity: float,
    model_version: str,
    top_features: list[schemas.FeatureContribution],
) -> tuple[str, int, int]:
    """Create or update a minimal incident row.

    M3-04 scope: each non-benign flow gets its own incident (keyed on flow_id
    for uniqueness). The real windowed correlator (key = src_ip,dst_ip,family,
    5-min window) is M3-05's responsibility.

    Returns (incident_id, created, updated).
    """
    mitre_id, mitre_name = policy.mitre_for(family)
    rs = policy.risk_score(verdict, confidence, severity, flow_count=1)
    rl = policy.risk_level(rs)
    now = _now_iso()
    top_json = json.dumps(
        [fc.model_dump(mode="json") for fc in top_features]
    )

    # Key: one incident per flow in M3-04 (M3-05 will merge by correlation window)
    incident_id = f"INC-{uuid.uuid4().hex[:12].upper()}"

    conn.execute(
        """
        INSERT INTO incidents (
            incident_id, status, verdict, attack_family,
            mitre_id, mitre_name, risk_score, risk_level, severity, max_confidence,
            flow_count, src_ip, dst_ip, dst_port,
            first_seen, last_seen,
            top_features_json, model_version, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            incident_id, "new", verdict.value, family.value,
            mitre_id, mitre_name, rs, rl, severity, confidence,
            1, meta.src_ip, meta.dst_ip, meta.dst_port,
            meta.observed_at.isoformat(), meta.observed_at.isoformat(),
            top_json, model_version, now,
        ),
    )
    return incident_id, 1, 0
