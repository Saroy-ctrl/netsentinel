"""Regenerate the JSON fixtures from the pydantic contracts.

    python -m nscore.contracts.fixtures.make_fixtures

Fixtures are what M3's mock API serves and what M4's dashboard renders
before any real model exists. Built through the models, so they are valid
by construction; tests/test_contracts.py re-validates them in CI.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from nscore.contracts.policy import confidence_band, mitre_for, priority_band, priority_score
from nscore.contracts.schemas import (
    ActionType,
    AnalystActionRecord,
    AttackFamily,
    Brief,
    DriftReport,
    DriftStatus,
    EvaluationReport,
    FeatureContribution,
    FeatureDrift,
    FlowMeta,
    FlowRecord,
    IncidentDetail,
    IncidentPage,
    IncidentStatus,
    IncidentSummary,
    LiveMetrics,
    LoaoResult,
    ModelInfo,
    PerClassMetrics,
    ScoreResult,
    Verdict,
)

OUT = Path(__file__).parent
T0 = datetime(2026, 10, 2, 9, 30, tzinfo=UTC)
MODEL = "nsb-0.0.0-fixture"

# Illustrative numbers only - real ones come from M2's evaluation_report.json.
FEATS = [
    FeatureContribution(feature="flow_iat_mean", value=12.0, shap_value=0.21, baseline_median=48210.0),
    FeatureContribution(feature="syn_flag_count", value=1.0, shap_value=0.17, baseline_median=0.0),
    FeatureContribution(feature="total_fwd_packets", value=1.0, shap_value=0.11, baseline_median=6.0),
    FeatureContribution(feature="init_win_bytes_forward", value=1024.0, shap_value=0.08, baseline_median=8192.0),
    FeatureContribution(feature="flow_duration", value=35.0, shap_value=0.05, baseline_median=61844.0),
]


def _incident(i: int, family: AttackFamily, verdict: Verdict, conf: float, flows: int,
              status: IncidentStatus, src: str, dport: int) -> IncidentSummary:
    tid, tname = mitre_for(family)
    score = priority_score(family, verdict, conf, flows)
    return IncidentSummary(
        incident_id=f"INC-{1000 + i}", status=status, verdict=verdict, attack_family=family,
        mitre_technique_id=tid, mitre_technique_name=tname, priority=score,
        priority_band=priority_band(score), max_confidence=conf, flow_count=flows,
        src_ip=src, dst_ip="192.168.10.50", dst_port=dport,
        first_seen=T0 + timedelta(minutes=i), last_seen=T0 + timedelta(minutes=i + 3),
        model_version=MODEL,
    )


def build() -> dict[str, object]:
    incidents = [
        _incident(1, AttackFamily.BOTNET, Verdict.KNOWN_ATTACK, 0.94, 37, IncidentStatus.NEW, "192.168.10.15", 8080),
        _incident(2, AttackFamily.UNKNOWN, Verdict.NOVEL_ANOMALY, 0.71, 112, IncidentStatus.NEW, "172.16.0.1", 443),
        _incident(3, AttackFamily.DDOS, Verdict.KNOWN_ATTACK, 0.99, 4210, IncidentStatus.ESCALATED, "172.16.0.1", 80),
        _incident(4, AttackFamily.BRUTE_FORCE, Verdict.KNOWN_ATTACK, 0.88, 260, IncidentStatus.ACKNOWLEDGED,
                  "205.174.165.73", 22),
        _incident(5, AttackFamily.PORTSCAN, Verdict.KNOWN_ATTACK, 0.97, 1580, IncidentStatus.NEW, "172.16.0.1", 0),
        _incident(6, AttackFamily.WEB_ATTACK, Verdict.KNOWN_ATTACK, 0.58, 3, IncidentStatus.DISMISSED_FP,
                  "172.16.0.1", 80),
    ]
    top = incidents[1]
    detail = IncidentDetail(
        **top.model_dump(),
        top_features=FEATS,
        sample_flow_ids=[f"F-{n}" for n in range(5)],
        actions=[AnalystActionRecord(action_id=1, incident_id=top.incident_id, analyst="asha",
                                     action=ActionType.ACKNOWLEDGE, note="looking", at=T0 + timedelta(minutes=6))],
        brief=Brief(
            incident_id=top.incident_id,
            text=("Possible novel activity from 172.16.0.1 to 192.168.10.50:443 across 112 flows. "
                  "No known attack family matched, but the traffic sits far outside normal behaviour: "
                  "inter-arrival times are ~4,000x shorter than typical and most flows carry a single SYN. "
                  "Worth reviewing: check whether 172.16.0.1 is an authorised scanner before escalating."),
            source="template", model_deployment=None,
            confidence_band=confidence_band(top.max_confidence), generated_at=T0 + timedelta(minutes=7),
        ),
    )
    flow = FlowRecord(
        meta=FlowMeta(flow_id="F-0", observed_at=T0, src_ip="172.16.0.1", dst_ip="192.168.10.50",
                      src_port=51234, dst_port=443, protocol=6),
        features={f.feature: f.value for f in FEATS},
        ground_truth="PortScan",
    )
    score = ScoreResult(flow_id="F-0", verdict=Verdict.NOVEL_ANOMALY, p_attack=0.31, anomaly_percentile=99.8,
                        attack_family=AttackFamily.UNKNOWN, family_confidence=None, top_features=FEATS,
                        incident_id=top.incident_id, model_version=MODEL, latency_ms=8.4)
    fams = [AttackFamily.BENIGN, AttackFamily.DOS, AttackFamily.DDOS, AttackFamily.PORTSCAN,
            AttackFamily.BRUTE_FORCE, AttackFamily.WEB_ATTACK, AttackFamily.BOTNET, AttackFamily.RARE]
    evaluation = EvaluationReport(
        model_version=MODEL, split_strategy="time-blocked per (day,label) 70/15/15",
        labels=fams,
        per_class=[PerClassMetrics(family=f, precision=0.9, recall=0.9, f1=0.9, fpr=0.01, support=1000, roc_auc=0.97)
                   for f in fams],
        confusion_matrix=[[1000 if r == c else 5 for c in range(len(fams))] for r in range(len(fams))],
        macro_f1=0.9, binary_roc_auc=0.98, binary_pr_auc=0.95, benign_fpr=0.012,
        loao=[LoaoResult(held_out_family=f, rf_only_recall=0.3, fusion_recall=0.7, benign_fpr=0.015)
              for f in fams[1:7]],
        limitations=["FIXTURE DATA - not real results"],
    )
    model = ModelInfo(model_version=MODEL, bundle_ref="local:artifacts/fixture", registry="local",
                      trained_at=T0, dataset="CICIDS2017 (corrected, Engelen et al. 2021)",
                      split_strategy=evaluation.split_strategy, feature_count=52,
                      thresholds={"tau_binary": 0.62, "tau_anomaly": 99.5}, operating_fpr_target=0.01,
                      metrics_summary={"macro_f1": 0.9, "binary_roc_auc": 0.98, "benign_fpr": 0.012})
    drift = DriftReport(computed_at=T0, window_size=2000, status=DriftStatus.WATCH, max_psi=0.18,
                        features=[FeatureDrift(feature="flow_iat_mean", psi=0.18, status=DriftStatus.WATCH),
                                  FeatureDrift(feature="syn_flag_count", psi=0.07, status=DriftStatus.OK)],
                        prediction_attack_rate=0.21, reference_attack_rate=0.17)
    metrics = LiveMetrics(flows_scored_total=48210, flows_per_sec_1m=212.5, latency_ms_p50=6.1, latency_ms_p95=14.8,
                          incidents_open=4, incidents_by_band={"P1": 2, "P2": 1, "P3": 1, "P4": 0},
                          analyst_confirmed_precision=0.83, fp_dismiss_rate=0.17, mtta_seconds=94.0)
    return {
        "flow_record.json": flow,
        "score_result.json": score,
        "incident_page.json": IncidentPage(items=incidents, total=len(incidents), limit=50, offset=0),
        "incident_detail.json": detail,
        "evaluation_report.json": evaluation,
        "model_info.json": model,
        "drift_report.json": drift,
        "live_metrics.json": metrics,
    }


def main() -> None:
    for name, obj in build().items():
        text = json.dumps(obj.model_dump(mode="json"), indent=2) + "\n"
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")  # LF on every OS so the CI diff is stable
        print("wrote", name)


if __name__ == "__main__":
    main()
