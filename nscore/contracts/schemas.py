"""NetSentinel shared contracts (v1).

Every component (ml/, api/, dashboard/, replay/) talks through these models.
They are the reason five people can build in parallel: code against the
schema + the JSON fixtures in ./fixtures, not against each other's code.

Changing anything here = PR approved by M3 (API owner) + one consumer,
and a CONTRACT_VERSION bump. See CONTRIBUTING.md.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1.1.0"  # 1.1.0: EvaluationReport.external (cross-network + real-world results)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# --------------------------------------------------------------------------- enums


class Verdict(StrEnum):
    BENIGN = "benign"
    KNOWN_ATTACK = "known_attack"  # RF binary head fired -> multiclass family assigned
    NOVEL_ANOMALY = "novel_anomaly"  # RF said benign, but benign-trained IsolationForest says "never seen this"


class AttackFamily(StrEnum):
    BENIGN = "BENIGN"
    DOS = "DoS"
    DDOS = "DDoS"
    PORTSCAN = "PortScan"
    BRUTE_FORCE = "BruteForce"
    WEB_ATTACK = "WebAttack"
    BOTNET = "Botnet"
    RARE = "Rare"  # Heartbleed / Infiltration / SQLi etc. merged: too few samples for their own class
    UNKNOWN = "Unknown"  # used only for NOVEL_ANOMALY verdicts


class IncidentStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    DISMISSED_FP = "dismissed_fp"  # analyst says false positive -> feeds live FP-rate metric
    RESOLVED = "resolved"


class ActionType(StrEnum):
    ACKNOWLEDGE = "acknowledge"
    ESCALATE = "escalate"
    DISMISS_FP = "dismiss_fp"
    CONFIRM = "confirm"  # analyst confirms true positive -> feeds analyst-confirmed precision
    RESOLVE = "resolve"
    NOTE = "note"


class DriftStatus(StrEnum):
    OK = "ok"  # PSI < 0.10
    WATCH = "watch"  # 0.10 <= PSI < 0.25
    ALERT = "alert"  # PSI >= 0.25 -> "consider retraining"


PriorityBand = Literal["P1", "P2", "P3", "P4"]
ConfidenceBand = Literal["high", "medium", "low"]


# --------------------------------------------------------------------------- ingest


class FlowMeta(_Model):
    """Identifiers kept OUT of the model's feature vector (they leak / don't generalise)."""

    flow_id: str
    observed_at: datetime
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: int = Field(ge=0, le=255, description="IANA protocol number (6=TCP, 17=UDP)")


class FlowRecord(_Model):
    """One CICFlowMeter flow. `features` keys = canonical names from feature_spec.json."""

    meta: FlowMeta
    features: dict[str, float]
    ground_truth: str | None = Field(
        default=None,
        description="Replay-only label for live demo scoring. NEVER read by the model.",
    )


class FlowBatch(_Model):
    flows: list[FlowRecord] = Field(min_length=1, max_length=500)


# --------------------------------------------------------------------------- scoring


class FeatureContribution(_Model):
    feature: str
    value: float = Field(description="Raw (unscaled) value - human readable")
    shap_value: float
    baseline_median: float | None = Field(
        default=None, description="Median of this feature in benign training traffic"
    )


class ScoreResult(_Model):
    flow_id: str
    verdict: Verdict
    p_attack: float = Field(ge=0, le=1, description="RF binary head probability")
    anomaly_percentile: float = Field(
        ge=0, le=100, description="IsolationForest score as percentile of benign validation traffic"
    )
    attack_family: AttackFamily
    family_confidence: float | None = Field(default=None, ge=0, le=1)
    top_features: list[FeatureContribution] = Field(default_factory=list, max_length=10)
    incident_id: str | None = None
    model_version: str
    latency_ms: float = Field(ge=0)


class ScoreBatchResponse(_Model):
    received: int
    results: list[ScoreResult]
    incidents_created: int
    incidents_updated: int


# --------------------------------------------------------------------------- incidents


class Brief(_Model):
    incident_id: str
    text: str
    source: Literal["azure_openai", "template"]
    model_deployment: str | None = None
    confidence_band: ConfidenceBand
    generated_at: datetime


class AnalystActionIn(_Model):
    action: ActionType
    note: str | None = Field(default=None, max_length=1000)


class AnalystActionRecord(_Model):
    action_id: int
    incident_id: str
    analyst: str
    action: ActionType
    note: str | None = None
    at: datetime


class IncidentSummary(_Model):
    incident_id: str
    status: IncidentStatus
    verdict: Verdict
    attack_family: AttackFamily
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    priority: int = Field(ge=0, le=100)
    priority_band: PriorityBand
    max_confidence: float = Field(ge=0, le=1)
    flow_count: int = Field(ge=1)
    src_ip: str
    dst_ip: str
    dst_port: int
    first_seen: datetime
    last_seen: datetime
    model_version: str


class IncidentDetail(IncidentSummary):
    top_features: list[FeatureContribution]
    sample_flow_ids: list[str] = Field(max_length=20)
    actions: list[AnalystActionRecord]
    brief: Brief | None = None


class IncidentPage(_Model):
    items: list[IncidentSummary]
    total: int
    limit: int
    offset: int


# --------------------------------------------------------------------------- model / evaluation


class PerClassMetrics(_Model):
    family: AttackFamily
    precision: float
    recall: float
    f1: float
    fpr: float
    support: int
    roc_auc: float | None = None


class LoaoResult(_Model):
    """Leave-One-Attack-family-Out: the family was removed from training entirely."""

    held_out_family: AttackFamily
    rf_only_recall: float
    fusion_recall: float  # RF + IsolationForest
    benign_fpr: float


class ExternalEvalResult(_Model):
    """Evaluation on data from a DIFFERENT network / period than training (docs/03 #3.2 P3, P4)."""

    dataset: str = Field(description="e.g. 'CSE-CIC-IDS2018 (corrected)' or 'LUFlow 2021-03'")
    protocol: Literal["cross_network", "cross_network_recalibrated", "real_world_temporal"]
    period: str | None = Field(default=None, description="time slice for temporal studies, e.g. '2021-03'")
    binary_recall: float
    benign_fpr: float
    roc_auc: float | None = None
    novel_recall: float | None = Field(
        default=None,
        description="recall on attack variants absent from training (e.g. DDoS-HOIC), "
        "or share of LUFlow 'outlier' flows flagged as novel",
    )
    max_psi: float | None = Field(default=None, description="largest feature PSI vs training reference")
    notes: str | None = None


class EvaluationReport(_Model):
    model_version: str
    split_strategy: str
    labels: list[AttackFamily]
    per_class: list[PerClassMetrics]
    confusion_matrix: list[list[int]]
    macro_f1: float
    binary_roc_auc: float
    binary_pr_auc: float
    benign_fpr: float
    loao: list[LoaoResult] = Field(default_factory=list)
    external: list[ExternalEvalResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ModelInfo(_Model):
    model_version: str
    bundle_ref: str = Field(description="e.g. azureml:netsentinel-bundle:3 or local:artifacts/bundle_v3")
    registry: Literal["azureml", "local"]
    trained_at: datetime
    dataset: str
    split_strategy: str
    feature_count: int
    thresholds: dict[str, float]
    operating_fpr_target: float
    metrics_summary: dict[str, float]
    contract_version: str = CONTRACT_VERSION


class BundleManifest(_Model):
    """manifest.json at the root of every model bundle (see docs/03_architecture.md #bundle)."""

    bundle_version: str
    created_at: datetime
    contract_version: str
    dataset: str
    split_strategy: str
    feature_spec_sha256: str
    files: dict[str, str] = Field(description="relative path -> sha256")
    metrics_summary: dict[str, float]
    tags: dict[str, str] = Field(default_factory=dict)


# --------------------------------------------------------------------------- ops


class FeatureDrift(_Model):
    feature: str
    psi: float = Field(ge=0)
    status: DriftStatus


class DriftReport(_Model):
    computed_at: datetime
    window_size: int
    status: DriftStatus
    max_psi: float
    features: list[FeatureDrift]
    prediction_attack_rate: float
    reference_attack_rate: float


class LiveMetrics(_Model):
    flows_scored_total: int
    flows_per_sec_1m: float
    latency_ms_p50: float
    latency_ms_p95: float
    incidents_open: int
    incidents_by_band: dict[str, int]
    analyst_confirmed_precision: float | None = Field(
        default=None, description="confirmed / (confirmed + dismissed_fp) over reviewed incidents"
    )
    fp_dismiss_rate: float | None = None
    mtta_seconds: float | None = Field(default=None, description="mean time to acknowledge")
