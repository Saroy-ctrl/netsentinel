"""M3-05: Incident Correlator.

Groups non-benign network flows into contextual SOC incidents within a rolling time window:
- Key: (src_ip, dst_ip, attack_family). Novel anomalies use "Unknown".
- Window: 5 minutes (300 seconds) based on flow.observed_at vs incident.last_seen.
- Closed incidents (status 'resolved' or 'dismissed_fp') are never merged into.
- Open incidents ('new', 'investigating', 'escalated') absorb matching flows within the window.
- On merge: flow_count += 1, max_confidence = max(...), running mean severity,
  advances last_seen, aggregates top-5 SHAP features by mean |shap|, recomputes risk score/level.
- On create: status='new', flow_count=1, first_seen=last_seen=observed_at.

Architecture references: docs/03_architecture.md §4.3, §4.4
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from nscore.contracts import policy, schemas
from nscore.contracts.schemas import AttackFamily, Verdict

logger = logging.getLogger(__name__)

CORRELATION_WINDOW_SECONDS = 300.0
CLOSED_STATUSES = ("resolved", "dismissed_fp")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_utc_datetime(dt_or_str: datetime | str) -> datetime:
    """Parse string or datetime to timezone-aware UTC datetime."""
    if isinstance(dt_or_str, datetime):
        if dt_or_str.tzinfo is None:
            return dt_or_str.replace(tzinfo=UTC)
        return dt_or_str.astimezone(UTC)
    s = dt_or_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _aggregate_top_features(
    existing_features_json: str | None,
    old_count: int,
    new_contributions: list[schemas.FeatureContribution],
) -> list[dict[str, Any]]:
    """Aggregate SHAP feature contributions across merged flows.

    Maintains running mean of shap values, ranks by mean |shap|,
    and returns top 5 formatted dicts.
    """
    if not new_contributions and not existing_features_json:
        return []

    # Map feature -> {sum_shap, value, baseline_median}
    feature_sums: dict[str, float] = {}
    feature_meta: dict[str, tuple[float, float | None]] = {}

    if existing_features_json:
        try:
            parsed = json.loads(existing_features_json)
            if isinstance(parsed, list):
                for item in parsed:
                    name = item.get("feature")
                    if name:
                        shap_val = float(item.get("shap_value", 0.0))
                        # Existing stored shap_value was the mean over old_count flows
                        feature_sums[name] = shap_val * old_count
                        feature_meta[name] = (
                            float(item.get("value", 0.0)),
                            item.get("baseline_median"),
                        )
        except Exception as exc:
            logger.warning("Correlator: failed to parse existing top_features_json: %s", exc)

    # Incorporate new contributions (1 flow)
    new_count = old_count + 1
    for fc in new_contributions:
        name = fc.feature
        shap_val = float(fc.shap_value)
        feature_sums[name] = feature_sums.get(name, 0.0) + shap_val
        # Update latest observed raw value and baseline median
        feature_meta[name] = (float(fc.value), fc.baseline_median)

    # Calculate mean shap per feature over new_count flows
    means: list[tuple[str, float, float, float | None]] = []
    for name, sum_shap in feature_sums.items():
        mean_shap = sum_shap / new_count
        raw_val, base_med = feature_meta[name]
        means.append((name, mean_shap, raw_val, base_med))

    # Rank by mean absolute SHAP descending, take top 5
    means.sort(key=lambda x: abs(x[1]), reverse=True)
    top_5 = means[:5]

    return [
        {
            "feature": name,
            "value": raw_val,
            "shap_value": round(mean_shap, 4),
            "baseline_median": base_med,
        }
        for name, mean_shap, raw_val, base_med in top_5
    ]


class IncidentCorrelator:
    """Stateful SQLite-backed incident correlator (M3-05)."""

    def __init__(self, window_seconds: float = CORRELATION_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds

    def correlate_flow(
        self,
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
        """Correlate a non-benign flow into an open incident or create a new one.

        Returns (incident_id, created_count, updated_count).
        """
        # Novel anomalies use "Unknown"
        if verdict is Verdict.NOVEL_ANOMALY or family is AttackFamily.UNKNOWN:
            family_key = AttackFamily.UNKNOWN.value
        else:
            family_key = family.value

        flow_time = _parse_utc_datetime(meta.observed_at)

        # Query candidate open incidents matching (src_ip, dst_ip, attack_family)
        # using the ix_inc_key index.
        cur = conn.execute(
            """
            SELECT incident_id, status, verdict, attack_family, severity,
                   max_confidence, flow_count, first_seen, last_seen, top_features_json
            FROM incidents
            WHERE src_ip = ?
              AND dst_ip = ?
              AND attack_family = ?
              AND status NOT IN ('resolved', 'dismissed_fp')
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (meta.src_ip, meta.dst_ip, family_key),
        )
        row = cur.fetchone()

        if row is not None:
            (
                inc_id,
                status,
                inc_verdict_str,
                inc_family_str,
                inc_sev,
                inc_max_conf,
                inc_flow_count,
                inc_first_seen_str,
                inc_last_seen_str,
                inc_top_json,
            ) = row

            inc_last_seen = _parse_utc_datetime(inc_last_seen_str)
            time_diff = abs((flow_time - inc_last_seen).total_seconds())

            if time_diff <= self.window_seconds:
                # Merge into existing open incident
                new_flow_count = inc_flow_count + 1
                new_max_conf = max(float(inc_max_conf), float(confidence))
                new_severity = (float(inc_sev) * inc_flow_count + float(severity)) / new_flow_count

                new_last_seen_dt = max(inc_last_seen, flow_time)
                new_last_seen_str = new_last_seen_dt.isoformat()

                # Recompute top 5 aggregated SHAP features
                aggregated_top = _aggregate_top_features(
                    inc_top_json,
                    inc_flow_count,
                    top_features,
                )
                new_top_json = json.dumps(aggregated_top)

                # Recompute risk score with burst factor for updated flow_count
                eff_verdict = Verdict(inc_verdict_str)
                eff_family = AttackFamily(inc_family_str)
                mitre_id, mitre_name = policy.mitre_for(eff_family)
                new_risk_score = policy.risk_score(
                    eff_verdict,
                    new_max_conf,
                    new_severity,
                    flow_count=new_flow_count,
                )
                new_risk_level = policy.risk_level(new_risk_score)
                now_str = _now_iso()

                conn.execute(
                    """
                    UPDATE incidents SET
                        flow_count = ?,
                        max_confidence = ?,
                        severity = ?,
                        last_seen = ?,
                        top_features_json = ?,
                        mitre_id = ?,
                        mitre_name = ?,
                        risk_score = ?,
                        risk_level = ?,
                        updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (
                        new_flow_count,
                        new_max_conf,
                        new_severity,
                        new_last_seen_str,
                        new_top_json,
                        mitre_id,
                        mitre_name,
                        new_risk_score,
                        new_risk_level,
                        now_str,
                        inc_id,
                    ),
                )
                return inc_id, 0, 1

        # No matching open incident within the window -> Create new incident
        incident_id = f"INC-{uuid.uuid4().hex[:12].upper()}"
        mitre_id, mitre_name = policy.mitre_for(family)
        initial_risk = policy.risk_score(verdict, confidence, severity, flow_count=1)
        initial_level = policy.risk_level(initial_risk)
        observed_iso = flow_time.isoformat()
        now_str = _now_iso()

        initial_top = [
            fc.model_dump(mode="json") for fc in top_features[:5]
        ]
        top_json = json.dumps(initial_top)

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
                incident_id,
                "new",
                verdict.value,
                family_key,
                mitre_id,
                mitre_name,
                initial_risk,
                initial_level,
                float(severity),
                float(confidence),
                1,
                meta.src_ip,
                meta.dst_ip,
                meta.dst_port,
                observed_iso,
                observed_iso,
                top_json,
                model_version,
                now_str,
            ),
        )
        return incident_id, 1, 0
