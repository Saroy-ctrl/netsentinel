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
import os
import time
from datetime import UTC, datetime

from api.app.correlator import CORRELATION_WINDOW_SECONDS, IncidentCorrelator
from nscore.bundle.loader import Bundle
from nscore.contracts import policy, schemas
from nscore.contracts.schemas import AttackFamily, Verdict
from nscore.detection.engine import DetectionEngine

logger = logging.getLogger(__name__)

# Exact TreeSHAP costs roughly 10-100 ms per flow, so a 500-flow attack batch would take seconds. Only the most
# suspicious flows of a batch are explained; the rest are still scored, persisted and correlated (model card §3).
DEFAULT_SHAP_MAX_PER_BATCH = 25


def _shap_cap() -> int:
    try:
        return max(0, int(os.environ.get("NS_SHAP_MAX_PER_BATCH", DEFAULT_SHAP_MAX_PER_BATCH)))
    except ValueError:
        return DEFAULT_SHAP_MAX_PER_BATCH


# Every incident touched by a batch gets at least one explained flow, even past the cap, up to this ceiling (a scan from
# hundreds of sources). Without it an incident whose flows all rank below the cap has no SHAP chart in the console.
SHAP_INCIDENT_CEILING = 100


def _select_for_shap(metas, verdicts, families, p_attack, cap: int) -> list[int]:
    """Flow indices to explain: the most suspicious flow of each incident group, then the most suspicious of the rest.

    Groups mirror the correlator: key (src_ip, dst_ip, family; novel anomalies -> Unknown), split wherever consecutive
    flows of a key are more than the correlation window apart (each such run becomes its own incident).
    Returned in batch order.
    """
    if cap <= 0:
        return []
    attacks = sorted((i for i, v in enumerate(verdicts) if v is not Verdict.BENIGN), key=lambda i: -float(p_attack[i]))

    by_key: dict[tuple, list[int]] = {}
    for i in attacks:
        family = AttackFamily.UNKNOWN if verdicts[i] is Verdict.NOVEL_ANOMALY else families[i]
        by_key.setdefault((metas[i].src_ip, metas[i].dst_ip, family), []).append(i)
    group_of: dict[int, tuple] = {}
    for key, members in by_key.items():
        run, last = 0, None
        for i in sorted(members, key=lambda j: metas[j].observed_at):
            t = metas[i].observed_at
            if last is not None and (t - last).total_seconds() > CORRELATION_WINDOW_SECONDS:
                run += 1
            group_of[i], last = (key, run), t

    seen, representatives = set(), []
    for i in attacks:  # most suspicious first, so each group's representative is its most suspicious flow
        if group_of[i] not in seen:
            seen.add(group_of[i])
            representatives.append(i)
    chosen = representatives[:max(cap, SHAP_INCIDENT_CEILING)]
    taken = set(chosen)
    chosen += [i for i in attacks if i not in taken][:max(0, cap - len(chosen))]
    return sorted(chosen)


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
        self.correlator = IncidentCorrelator()
        self.model_version = bundle.version

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_batch(
        self,
        batch: schemas.FlowBatch,
        conn,  # sqlite3.Connection from db_session
        drift_monitor=None,  # DriftMonitor | None — optional, avoids circular import
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
        non_benign_idx = _select_for_shap(
            [fr.meta for fr in flow_records], det.verdict, det.family, det.p_attack, _shap_cap()
        )
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
                incident_id, inc_created, inc_updated = self.correlator.correlate_flow(
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

        # Feed the drift monitor only AFTER the commit: it persists snapshots on its own connection, which blocks
        # ("database is locked") while this connection still holds uncommitted writes. (M3-08)
        if drift_monitor is not None and det.X is not None:
            verdict_strs = [det.verdict[i].value for i in range(len(flow_records))]
            drift_monitor.observe(det.X, verdict_strs)

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
