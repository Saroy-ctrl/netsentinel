"""Drift & Health Page — M4-07.

Features
--------
* Population Stability Index (PSI) horizontal bar chart with 0.10 and 0.25 reference lines
* Global drift status banner (OK / WATCH / ALERT) with actionable runbook guidance
* Pipeline health metrics tiles (throughput flows/s, p50 and p95 latency, total flows)
* Attack prevalence shift indicator (Observed window attack rate vs Reference baseline)
* Detailed feature drift tabular breakdown
* Analyst sidebar integration
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="Drift & Health · NetSentinel",
    page_icon="📡",
    layout="wide",
)

import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import APIError, get_drift, get_live_metrics  # noqa: E402

theme.inject_css()
theme.render_api_down_banner()
theme.render_full_sidebar()

# ---------------------------------------------------------------------------
# Helpers & Chart Builders
# ---------------------------------------------------------------------------


def _fmt_ts(val: Any) -> str:
    """Format datetime nicely."""
    try:
        return val.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(val)


def _build_psi_chart(features_drift: list[Any]) -> go.Figure:
    """Build horizontal bar chart with 0.10 and 0.25 PSI threshold lines."""
    # Sort features by PSI ascending so largest is on top
    sorted_items = sorted(features_drift, key=lambda x: x.psi)
    names = [item.feature for item in sorted_items]
    psi_values = [item.psi for item in sorted_items]

    colors = []
    for p in psi_values:
        if p >= 0.25:
            colors.append(theme.CLR_DRIFT_ALERT)
        elif p >= 0.10:
            colors.append(theme.CLR_DRIFT_WATCH)
        else:
            colors.append(theme.CLR_DRIFT_OK)

    fig = go.Figure()

    fig.add_trace(
        go.Bar(
            x=psi_values,
            y=names,
            orientation="h",
            marker=dict(
                color=colors,
                line=dict(color=theme.BORDER_SUBTLE, width=1),
            ),
            text=[f"{p:.3f}" for p in psi_values],
            textposition="auto",
            textfont=dict(color=theme.TXT_PRIMARY, size=11),
            hovertemplate="<b>%{y}</b><br>PSI: %{x:.4f}<extra></extra>",
        )
    )

    # Reference lines at 0.10 and 0.25
    fig.add_vline(
        x=0.10,
        line_dash="dash",
        line_color=theme.CLR_DRIFT_WATCH,
        line_width=1.5,
        annotation_text="Watch (0.10)",
        annotation_position="top right",
        annotation_font=dict(color=theme.CLR_DRIFT_WATCH, size=11),
    )
    fig.add_vline(
        x=0.25,
        line_dash="dash",
        line_color=theme.CLR_DRIFT_ALERT,
        line_width=1.5,
        annotation_text="Alert (0.25)",
        annotation_position="top right",
        annotation_font=dict(color=theme.CLR_DRIFT_ALERT, size=11),
    )

    max_x = max([0.30] + psi_values) * 1.15

    fig.update_layout(
        margin=dict(l=10, r=20, t=30, b=30),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme.TXT_PRIMARY, family=theme.FONT_SANS),
        xaxis=dict(
            title="Population Stability Index (PSI)",
            gridcolor=theme.BORDER_SUBTLE,
            zerolinecolor=theme.BORDER_SUBTLE,
            range=[0, max_x],
        ),
        yaxis=dict(gridcolor=theme.BORDER_SUBTLE),
        height=max(260, len(names) * 38),
    )
    return fig


# ---------------------------------------------------------------------------
# Data Fetching
# ---------------------------------------------------------------------------

try:
    drift = get_drift()
    metrics = get_live_metrics()
except APIError as exc:
    st.markdown(
        theme.error_state(
            "Could Not Load Drift & Telemetry Data",
            str(exc),
            "Ensure the drift monitoring service is active or verify backend connectivity.",
        ),
        unsafe_allow_html=True,
    )
    st.stop()


# ---------------------------------------------------------------------------
# Header & Refresh Control
# ---------------------------------------------------------------------------

col_title, col_btn = st.columns([4, 1])
with col_title:
    st.title("📡 Drift & Health Monitor")
    st.caption(
        f"Evaluated at: {_fmt_ts(drift.computed_at)} &nbsp;|&nbsp; "
        f"Rolling Window: {drift.window_size:,} flows"
    )
with col_btn:
    if st.button("🔄 Refresh Data", width="stretch", key="_btn_refresh_drift"):
        st.rerun()


# ---------------------------------------------------------------------------
# Status Banner
# ---------------------------------------------------------------------------

st.markdown(theme.drift_status_banner(drift.status.value), unsafe_allow_html=True)

if drift.status.value == "alert":
    st.error(
        "🚨 **Action Required: Concept Drift Exceeded Safety Threshold (PSI ≥ 0.25)**  \n"
        "Feature distributions in the current traffic window deviate significantly from baseline training data. "
        "Detection precision and novel anomaly separation may be degraded.  \n"
        "**Recommended remediation:** Refit threshold gates and IsolationForest on a label-free recent benign "
        "traffic window, or retrain the bundle following `docs/runbook_retrain.md`.",
        icon="🚨",
    )
elif drift.status.value == "watch":
    st.warning(
        "⚠️ **Notice: Mild Distribution Shift Detected (0.10 ≤ PSI < 0.25)**  \n"
        "One or more features show moderate divergence from the reference baseline. "
        "Continue active monitoring.",
        icon="⚠️",
    )

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Health & Throughput KPI Tiles
# ---------------------------------------------------------------------------

st.subheader("⚡ Pipeline Throughput & Latency SLA")

k1, k2, k3, k4, k5 = st.columns(5)
with k1:
    st.metric(
        "Throughput",
        f"{metrics.flows_per_sec_1m:.1f} /s",
        delta=f"{metrics.flows_scored_total:,} total flows",
        delta_color="off",
    )
    st.caption("1-minute rolling rate")

with k2:
    st.metric("p50 Latency", f"{metrics.latency_ms_p50:.1f} ms")
    st.caption("Median flow scoring time")

with k3:
    st.metric("p95 Latency", f"{metrics.latency_ms_p95:.1f} ms")
    st.caption("Tail inference & SHAP time")

with k4:
    psi_color = (
        theme.CLR_DRIFT_ALERT
        if drift.max_psi >= 0.25
        else (theme.CLR_DRIFT_WATCH if drift.max_psi >= 0.10 else theme.CLR_DRIFT_OK)
    )
    st.metric("Max Feature PSI", f"{drift.max_psi:.3f}")
    st.markdown(
        f"<span style='color:{psi_color};font-weight:700;font-size:0.80rem;text-transform:uppercase;'>"
        f"Status: {drift.status.value}</span>",
        unsafe_allow_html=True,
    )

with k5:
    st.metric("Window Size", f"{drift.window_size:,}")
    st.caption("Transformed flow sample")

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# PSI Chart & Threshold Reference
# ---------------------------------------------------------------------------

col_chart, col_prevalence = st.columns([3, 2])

with col_chart:
    st.subheader("📊 Feature PSI vs Reference Thresholds")
    st.caption(
        "Green: Stable (< 0.10) &nbsp;|&nbsp; Amber: Watch (0.10–0.25) &nbsp;|&nbsp; Red: Alert (≥ 0.25)"
    )
    if drift.features:
        fig_psi = _build_psi_chart(drift.features)
        st.plotly_chart(fig_psi, width="stretch")
    else:
        st.markdown(
            theme.empty_state(
                "📡",
                "No Feature Drift Records",
                "No features have accumulated enough flows in the current window to compute PSI.",
            ),
            unsafe_allow_html=True,
        )

with col_prevalence:
    st.subheader("📈 Traffic Attack Rate Shift")
    st.caption("Share of recent flows flagged vs the rate expected on normal traffic (the false-alarm budget)")

    diff_rate = drift.prediction_attack_rate - drift.reference_attack_rate
    delta_str = f"{diff_rate:+.1%}"

    st.metric(
        "Current Window Attack Rate",
        f"{drift.prediction_attack_rate:.1%}",
        delta=f"{delta_str} vs expected",
        delta_color="inverse",
    )
    st.metric("Expected on Normal Traffic", f"{drift.reference_attack_rate:.1%}")

    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:6px;padding:12px 14px;font-size:0.84rem;color:{theme.TXT_SECONDARY};margin-top:14px;'>"
        f"<strong>Prevalence Interpretation:</strong><br>"
        f"A sharp increase in predicted attack rate alongside elevated feature PSI indicates an active "
        f"attack wave or flood. A shift in attack rate with normal PSI suggests changes in ambient attack volume "
        f"without structural distribution collapse."
        f"</div>",
        unsafe_allow_html=True,
    )

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Feature Breakdown Table
# ---------------------------------------------------------------------------

st.subheader("📋 Feature Drift Tabular Breakdown")

if drift.features:
    table_rows = []
    for f in sorted(drift.features, key=lambda x: x.psi, reverse=True):
        if f.psi >= 0.25:
            guidance = "Alert — Significant distribution shift. Retrain / recalibrate."
        elif f.psi >= 0.10:
            guidance = "Watch — Moderate distribution shift. Monitor closely."
        else:
            guidance = "Stable — Feature distribution matches baseline."

        table_rows.append(
            {
                "Feature Name": f.feature,
                "PSI Value": f"{f.psi:.4f}",
                "Status": f.status.value.upper(),
                "Operational Guidance": guidance,
            }
        )

    st.dataframe(pd.DataFrame(table_rows), width="stretch", hide_index=True)
else:
    st.info("No feature-level details to display.")
