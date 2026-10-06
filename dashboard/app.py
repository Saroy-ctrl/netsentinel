"""NetSentinel SOC Dashboard — Executive Command Center (M4-10).

Features
--------
* Universal API-down banner and connectivity monitor
* Full-featured, consistent sidebar across all pages
* Executive SOC summary cards (Open Incidents, Throughput, MTTA, Precision)
* Quick-launch navigation cards to all 5 functional pages
* Dual-engine fusion architecture overview
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# ── make sure the repo root is on sys.path so `nscore` is importable ──────────
_REPO_ROOT = Path(__file__).parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ── page config (must be the first Streamlit call) ─────────────────────────────
st.set_page_config(
    page_title="NetSentinel SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── late imports (after path fix) ──────────────────────────────────────────────
import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import (  # noqa: E402
    APIError,
    get_live_metrics,
    get_model_info,
)

theme.inject_css()
theme.render_api_down_banner()
theme.render_full_sidebar()

# ---------------------------------------------------------------------------
# Executive Header & System Status
# ---------------------------------------------------------------------------

try:
    model = get_model_info()
    model_version = model.model_version
    schema_label = model.feature_schema
except APIError:
    model_version = "Unknown"
    schema_label = "cic"

col_title, col_status = st.columns([3, 1])
with col_title:
    st.markdown(
        f"<div style='display:flex;align-items:center;gap:14px;'>"
        f"<h1 style='margin:0;font-size:2.2rem;'>🛡️ NetSentinel SOC Console</h1>"
        f"{theme.bundle_badge(schema_label, model_version)}"
        f"</div>"
        f"<div style='font-size:0.92rem;color:{theme.TXT_SECONDARY};margin-top:4px;'>"
        f"Real-time network anomaly detection, multi-factor risk scoring, and automated SOC triage."
        f"</div>",
        unsafe_allow_html=True,
    )

with col_status:
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:6px;padding:8px 12px;text-align:right;margin-top:6px;'>"
        f"<span style='color:{theme.CLR_DRIFT_OK};font-weight:700;'>● System Active</span> &nbsp;|&nbsp; "
        f"<span style='color:{theme.TXT_MUTED};font-size:0.80rem;'>Contract v2.1.0</span>"
        f"</div>",
        unsafe_allow_html=True,
    )

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Executive KPI Row
# ---------------------------------------------------------------------------

try:
    metrics = get_live_metrics()
    high_cnt = metrics.incidents_by_level.get("HIGH", 0)
    med_cnt = metrics.incidents_by_level.get("MEDIUM", 0)
    low_cnt = metrics.incidents_by_level.get("LOW", 0)
    prec_val = (
        f"{metrics.analyst_confirmed_precision:.1%}"
        if metrics.analyst_confirmed_precision is not None
        else "—"
    )
    mtta_val = (
        f"{metrics.mtta_seconds:.0f} s"
        if metrics.mtta_seconds is not None
        else "—"
    )

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric(
            "Open Incidents",
            f"{metrics.incidents_open}",
            delta=f"{high_cnt} HIGH · {med_cnt} MED",
            delta_color="inverse",
        )
        st.caption(f"Triage queue ({high_cnt} critical, {low_cnt} low priority)")

    with k2:
        st.metric(
            "Pipeline Throughput",
            f"{metrics.flows_per_sec_1m:.0f} flows/s",
            delta=f"{metrics.flows_scored_total:,} total flows",
            delta_color="off",
        )
        st.caption("1-minute rolling traffic rate")

    with k3:
        st.metric(
            "Mean Time to Acknowledge",
            mtta_val,
            delta="SLA Target: < 120 s",
            delta_color="normal",
        )
        st.caption("Response velocity from first alert")

    with k4:
        st.metric(
            "Confirmed Precision",
            prec_val,
            delta=f"FP dismiss: {metrics.fp_dismiss_rate:.1%}"
            if metrics.fp_dismiss_rate is not None
            else "—",
            delta_color="normal",
        )
        st.caption("Analyst-reviewed accuracy")

except APIError as exc:
    st.markdown(
        theme.error_state(
            "Live Telemetry Unavailable",
            str(exc),
            "Ensure backend service is running or switch to offline fixtures.",
        ),
        unsafe_allow_html=True,
    )

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Navigation Cards
# ---------------------------------------------------------------------------

st.subheader("🚀 Operational Console Modules")

col_n1, col_n2, col_n3 = st.columns(3)

with col_n1:
    st.markdown(
        f"<div class='ns-card ns-card-high' style='min-height:160px;'>"
        f"<h3 style='margin:0 0 6px 0;'>📋 Live Queue</h3>"
        f"<div style='font-size:0.86rem;color:{theme.TXT_SECONDARY};margin-bottom:12px;'>"
        f"Real-time 3-second streaming incident queue sorted by multi-factor risk score. "
        f"Supports filtering by status, verdict, attack family, and risk tier."
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    if st.button("Open Live Queue →", key="_nav_queue", width="stretch"):
        st.switch_page("pages/1_Live_Queue.py")

with col_n2:
    st.markdown(
        f"<div class='ns-card ns-card-medium' style='min-height:160px;'>"
        f"<h3 style='margin:0 0 6px 0;'>🔍 Incident Detail</h3>"
        f"<div style='font-size:0.86rem;color:{theme.TXT_SECONDARY};margin-bottom:12px;'>"
        f"Deep inspection featuring confidence × severity × burst breakdown, TreeSHAP feature attribution, "
        f"'vs normal' baseline table, MITRE mappings, and LLM triage brief."
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    if st.button("Open Incident Detail →", key="_nav_detail", width="stretch"):
        st.switch_page("pages/2_Incident_Detail.py")

with col_n3:
    st.markdown(
        f"<div class='ns-card' style='border-left-color:{theme.CLR_NOVEL_ANOMALY};min-height:160px;'>"
        f"<h3 style='margin:0 0 6px 0;'>📊 Model & Evaluation</h3>"
        f"<div style='font-size:0.86rem;color:{theme.TXT_SECONDARY};margin-bottom:12px;'>"
        f"Zero-day generalization via Leave-One-Attack-Out (LOAO), confusion matrices, operating FPR budget, "
        f"and real-world LUFlow results month by month."
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    if st.button("Open Model & Evaluation →", key="_nav_eval", width="stretch"):
        st.switch_page("pages/3_Model_Evaluation.py")

st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

col_n4, col_n5 = st.columns(2)

with col_n4:
    st.markdown(
        f"<div class='ns-card ns-card-low' style='border-left-color:{theme.CLR_CONF_HIGH};min-height:140px;'>"
        f"<h3 style='margin:0 0 6px 0;'>📡 Drift & Health Monitor</h3>"
        f"<div style='font-size:0.86rem;color:{theme.TXT_SECONDARY};margin-bottom:12px;'>"
        f"Population Stability Index (PSI) tracking against 0.10 (watch) and 0.25 (alert) thresholds. "
        f"Pipeline throughput and latency SLA monitoring."
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    if st.button("Open Drift & Health →", key="_nav_drift", width="stretch"):
        st.switch_page("pages/4_Drift_Health.py")

with col_n5:
    st.markdown(
        f"<div class='ns-card' style='border-left-color:{theme.CLR_DRIFT_OK};min-height:140px;'>"
        f"<h3 style='margin:0 0 6px 0;'>📈 Analyst Metrics</h3>"
        f"<div style='font-size:0.86rem;color:{theme.TXT_SECONDARY};margin-bottom:12px;'>"
        f"SOC analyst closed-loop telemetry: confirmed precision, false positive dismissal rates, MTTA, "
        f"and team workload distribution."
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )
    if st.button("Open Analyst Metrics →", key="_nav_metrics", width="stretch"):
        st.switch_page("pages/5_Analyst_Metrics.py")

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Architecture Summary
# ---------------------------------------------------------------------------

st.subheader("⚙️ Defense Architecture & Capabilities")

col_a1, col_a2, col_a3 = st.columns(3)

with col_a1:
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:6px;padding:14px 16px;line-height:1.5;font-size:0.86rem;'>"
        f"<h4 style='color:{theme.CLR_HIGH};margin-top:0;'>1. Detect, then Name</h4>"
        f"A Random Forest decides 'attack or not' at a strict 0.1% false-alarm budget; a second forest "
        f"names the family. When it cannot, the alert is labelled a novel anomaly instead of guessing "
        f"(measured on held-out families)."
        f"</div>",
        unsafe_allow_html=True,
    )

with col_a2:
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:6px;padding:14px 16px;line-height:1.5;font-size:0.86rem;'>"
        f"<h4 style='color:{theme.CLR_CONF_HIGH};margin-top:0;'>2. Explainable Triage</h4>"
        f"Computes exact TreeSHAP attribution and compares observed feature shifts against benign training "
        f"medians. Maps confirmed attacks directly to MITRE ATT&CK techniques."
        f"</div>",
        unsafe_allow_html=True,
    )

with col_a3:
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:6px;padding:14px 16px;line-height:1.5;font-size:0.86rem;'>"
        f"<h4 style='color:{theme.CLR_DRIFT_OK};margin-top:0;'>3. Drift Watch</h4>"
        f"Rolling PSI on the traffic the model calls normal, against normal training traffic: a warning to "
        f"re-check the model. On real honeypot traffic, detection held through drifted months "
        f"(precision 98.6%, recall 99.9%)."
        f"</div>",
        unsafe_allow_html=True,
    )
