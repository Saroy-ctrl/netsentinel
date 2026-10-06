"""Analyst Metrics Page — M4-08.

Features
--------
* Confirmed precision (confirmed / (confirmed + dismissed_fp)) with context card
* FP dismiss rate (1 - precision) with interpretation
* MTTA — Mean Time to Acknowledge in seconds + human-readable conversion
* Actions per analyst — breakdown from session-state audit trail
* Rolling metric tiles (live from /v1/metrics fixture)
* Session-action timeline — all analyst actions taken this session
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="Analyst Metrics · NetSentinel",
    page_icon="📈",
    layout="wide",
)

import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import APIError, get_live_metrics  # noqa: E402

theme.inject_css()
theme.render_api_down_banner()
theme.render_full_sidebar()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mtta_label(seconds: float | None) -> str:
    """Format MTTA seconds into human-readable form."""
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.2f} hr"


def _precision_color(prec: float | None) -> str:
    """Return a colour token for the precision value."""
    if prec is None:
        return theme.TXT_MUTED
    if prec >= 0.85:
        return theme.CLR_DRIFT_OK
    if prec >= 0.70:
        return theme.CLR_MEDIUM
    return theme.CLR_HIGH


def _build_actions_per_analyst_chart(
    actions: list[Any],
) -> go.Figure | None:
    """Build a horizontal bar chart breaking down actions per analyst identity."""
    if not actions:
        return None

    counts: Counter[str] = Counter(a.analyst for a in actions)
    analysts = list(counts.keys())
    values = [counts[a] for a in analysts]

    fig = go.Figure(
        go.Bar(
            x=values,
            y=analysts,
            orientation="h",
            marker=dict(
                color=theme.CLR_CONF_HIGH,
                line=dict(color=theme.BORDER_SUBTLE, width=1),
            ),
            text=values,
            textposition="auto",
            hovertemplate="<b>%{y}</b><br>Actions: %{x}<extra></extra>",
        )
    )
    fig.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme.TXT_PRIMARY, family=theme.FONT_SANS),
        xaxis=dict(
            title="Actions Taken",
            gridcolor=theme.BORDER_SUBTLE,
            dtick=1,
        ),
        yaxis=dict(gridcolor=theme.BORDER_SUBTLE),
        height=max(180, len(analysts) * 42),
    )
    return fig


def _build_action_type_breakdown(actions: list[Any]) -> go.Figure | None:
    """Build a donut chart for action type distribution."""
    if not actions:
        return None

    counts: Counter[str] = Counter(a.action.value for a in actions)
    _action_colors = {
        "acknowledge": "#00838F",
        "escalate": theme.CLR_HIGH,
        "confirm": theme.CLR_DRIFT_OK,
        "dismiss_fp": theme.CLR_LOW,
        "resolve": "#1565C0",
        "note": theme.TXT_MUTED,
    }
    labels = list(counts.keys())
    values = list(counts.values())
    colors = [_action_colors.get(label, theme.CLR_LOW) for label in labels]

    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.55,
            marker=dict(
                colors=colors,
                line=dict(color=theme.BG_PAGE, width=2),
            ),
            textinfo="label+percent",
            textfont=dict(color=theme.TXT_PRIMARY, size=11),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
        )
    )
    fig.update_layout(
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme.TXT_PRIMARY, family=theme.FONT_SANS),
        showlegend=True,
        legend=dict(font=dict(size=11, color=theme.TXT_SECONDARY)),
        height=240,
    )
    return fig


def _fmt_ts(val: Any) -> str:
    try:
        return val.strftime("%H:%M:%S")
    except Exception:
        return str(val)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

try:
    metrics = get_live_metrics()
except APIError as exc:
    st.markdown(
        theme.error_state(
            "Could Not Load Analyst Performance Metrics",
            str(exc),
            "Ensure the metrics aggregation service is active or verify backend connectivity.",
        ),
        unsafe_allow_html=True,
    )
    st.stop()

session_actions: list[Any] = st.session_state.get("_global_analyst_actions", [])
analyst_name, analyst_role, x_analyst_header = theme.get_analyst()

# ---------------------------------------------------------------------------
# Page Header
# ---------------------------------------------------------------------------

st.title("📈 Analyst Performance Metrics")
st.caption(
    "Live metrics are aggregated from the API. Session metrics reflect actions taken "
    "during this browser session and reset on page reload."
)

st.markdown(theme.divider(), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# KPI Tiles — Live Server Metrics
# ---------------------------------------------------------------------------

st.subheader("🌐 Live SOC Performance (Server-Aggregated)")

prec = metrics.analyst_confirmed_precision
fp_rate = metrics.fp_dismiss_rate
mtta = metrics.mtta_seconds

prec_color = _precision_color(prec)

c1, c2, c3, c4 = st.columns(4)

with c1:
    prec_str = f"{prec:.1%}" if prec is not None else "—"
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:8px;padding:14px 16px;text-align:center;'>"
        f"<div style='font-size:0.75rem;color:{theme.TXT_MUTED};text-transform:uppercase;"
        f"letter-spacing:0.06em;margin-bottom:4px;'>Confirmed Precision</div>"
        f"<div style='font-size:2.4rem;font-weight:800;color:{prec_color};'>{prec_str}</div>"
        f"<div style='font-size:0.75rem;color:{theme.TXT_SECONDARY};margin-top:4px;'>"
        f"confirmed / (confirmed + dismissed_fp)</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

with c2:
    fp_str = f"{fp_rate:.1%}" if fp_rate is not None else "—"
    fp_color = (
        theme.CLR_DRIFT_OK if fp_rate is not None and fp_rate < 0.10
        else (theme.CLR_MEDIUM if fp_rate is not None and fp_rate < 0.25 else theme.CLR_HIGH)
    )
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:8px;padding:14px 16px;text-align:center;'>"
        f"<div style='font-size:0.75rem;color:{theme.TXT_MUTED};text-transform:uppercase;"
        f"letter-spacing:0.06em;margin-bottom:4px;'>FP Dismiss Rate</div>"
        f"<div style='font-size:2.4rem;font-weight:800;color:{fp_color};'>{fp_str}</div>"
        f"<div style='font-size:0.75rem;color:{theme.TXT_SECONDARY};margin-top:4px;'>"
        f"dismissed_fp / total reviewed</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

with c3:
    mtta_str = _mtta_label(mtta)
    mtta_color = (
        theme.CLR_DRIFT_OK if mtta is not None and mtta < 120
        else (theme.CLR_MEDIUM if mtta is not None and mtta < 300 else theme.CLR_HIGH)
    )
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:8px;padding:14px 16px;text-align:center;'>"
        f"<div style='font-size:0.75rem;color:{theme.TXT_MUTED};text-transform:uppercase;"
        f"letter-spacing:0.06em;margin-bottom:4px;'>MTTA</div>"
        f"<div style='font-size:2.4rem;font-weight:800;color:{mtta_color};'>{mtta_str}</div>"
        f"<div style='font-size:0.75rem;color:{theme.TXT_SECONDARY};margin-top:4px;'>"
        f"mean time to first acknowledge</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

with c4:
    total_session = len(session_actions)
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:8px;padding:14px 16px;text-align:center;'>"
        f"<div style='font-size:0.75rem;color:{theme.TXT_MUTED};text-transform:uppercase;"
        f"letter-spacing:0.06em;margin-bottom:4px;'>Session Actions</div>"
        f"<div style='font-size:2.4rem;font-weight:800;color:{theme.CLR_CONF_HIGH};'>"
        f"{total_session}</div>"
        f"<div style='font-size:0.75rem;color:{theme.TXT_SECONDARY};margin-top:4px;'>"
        f"actions taken this browser session</div>"
        f"</div>",
        unsafe_allow_html=True,
    )

# Interpretation card
if prec is None:
    prec_msg = "Precision data unavailable — no analyst reviews recorded yet."
elif prec >= 0.85:
    prec_msg = "Model precision is healthy — analyst-confirmed classifications are accurate."
else:
    prec_msg = "Precision is below 85% — review SHAP feature attribution and refine thresholds."

if mtta is None:
    mtta_msg = "MTTA data unavailable."
elif mtta < 120:
    mtta_msg = "Excellent response time (< 2 min)."
elif mtta < 300:
    mtta_msg = "Acceptable response time (2–5 min)."
else:
    mtta_msg = "MTTA exceeds 5 minutes — consider staffing review."

st.markdown(
    f"<div style='background:{theme.BG_CARD};border-left:4px solid {prec_color};"
    f"border-radius:0 6px 6px 0;padding:10px 14px;font-size:0.84rem;"
    f"color:{theme.TXT_SECONDARY};margin:12px 0;'>"
    f"<strong>Precision:</strong> {prec_msg}"
    f" &nbsp;|&nbsp; "
    f"<strong>MTTA:</strong> {mtta_msg}"
    f"</div>",
    unsafe_allow_html=True,
)

st.markdown(theme.divider(), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session-Based: Actions per Analyst & Action Type Breakdown
# ---------------------------------------------------------------------------

st.subheader("👥 Session Analytics — Actions per Analyst")

if session_actions:
    col_bar, col_donut = st.columns([2, 1])

    with col_bar:
        st.markdown("**Actions by Analyst Identity**")
        fig_analyst = _build_actions_per_analyst_chart(session_actions)
        if fig_analyst:
            st.plotly_chart(fig_analyst, width="stretch")

    with col_donut:
        st.markdown("**Action Type Distribution**")
        fig_types = _build_action_type_breakdown(session_actions)
        if fig_types:
            st.plotly_chart(fig_types, width="stretch")

    # Per-analyst tabular breakdown
    st.markdown("**Per-Analyst Action Summary**")
    analyst_action_map: dict[str, Counter] = defaultdict(Counter)
    for act in session_actions:
        analyst_action_map[act.analyst][act.action.value] += 1

    all_action_types = sorted({a.action.value for a in session_actions})
    table_rows = []
    for analyst, counts in sorted(analyst_action_map.items(), key=lambda x: -sum(x[1].values())):
        row: dict[str, str | int] = {"Analyst": analyst, "Total": sum(counts.values())}
        for atype in all_action_types:
            row[atype.replace("_", " ").title()] = counts.get(atype, 0)
        table_rows.append(row)

    st.dataframe(pd.DataFrame(table_rows), width="stretch", hide_index=True)

else:
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:8px;padding:32px;text-align:center;color:{theme.TXT_MUTED};'>"
        f"No analyst actions recorded in this session yet.<br>"
        f"<span style='font-size:0.82rem;'>Take actions on the "
        f"<a href='#' style='color:{theme.CLR_CONF_HIGH};'>Incident Detail</a> page "
        f"to populate session analytics.</span>"
        f"</div>",
        unsafe_allow_html=True,
    )

st.markdown(theme.divider(), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session Audit Timeline
# ---------------------------------------------------------------------------

st.subheader("📜 Session Action Audit Trail")

if session_actions:
    sorted_actions = sorted(session_actions, key=lambda a: a.at, reverse=True)
    for act in sorted_actions:
        note_html = (
            f"<br><span style='color:{theme.TXT_SECONDARY};font-size:0.82rem;'>"
            f"Note: \"{act.note}\"</span>"
            if act.note else ""
        )
        st.markdown(
            f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
            f"border-radius:6px;padding:10px 16px;margin-bottom:6px;"
            f"display:flex;align-items:center;gap:12px;flex-wrap:wrap;'>"
            f"{theme.status_pill(act.action.value)}&nbsp;"
            f"<span style='font-family:{theme.FONT_MONO};font-size:0.82rem;color:{theme.CLR_CONF_HIGH};'>"
            f"{act.incident_id}</span>&nbsp;"
            f"<span style='color:{theme.TXT_PRIMARY};font-weight:600;'>{act.analyst}</span>&nbsp;"
            f"<span style='color:{theme.TXT_MUTED};font-size:0.78rem;'>{_fmt_ts(act.at)} UTC</span>"
            f"<span style='font-family:{theme.FONT_MONO};font-size:0.72rem;color:{theme.TXT_MUTED};'>"
            f"(action_id: {act.action_id})</span>"
            f"{note_html}"
            f"</div>",
            unsafe_allow_html=True,
        )
else:
    st.markdown(
        f"<div style='color:{theme.TXT_MUTED};font-size:0.85rem;'>No actions recorded yet.</div>",
        unsafe_allow_html=True,
    )

st.markdown(theme.divider(), unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Current Analyst Identity
# ---------------------------------------------------------------------------

st.subheader("🔑 Active Analyst Session")
st.markdown(theme.analyst_badge(analyst_name, analyst_role), unsafe_allow_html=True)
st.caption(
    f"HTTP header on actions: `X-Analyst: {x_analyst_header}` &nbsp;|&nbsp; "
    f"Change name/role in the sidebar sign-in panel."
)
