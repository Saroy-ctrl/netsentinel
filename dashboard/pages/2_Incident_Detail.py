"""Incident Detail Page — M4-04.

Features
--------
* Confidence × severity × burst risk breakdown
* SHAP bar chart (Plotly)
* vs-normal comparison table (value vs benign median)
* MITRE badge/link (linking to attack.mitre.org)
* Metadata (IPs, ports, protocols, flow count, time window, sample flow IDs)
* Brief panel (loading, LLM or template label, confidence band, regeneration)
* Action buttons with note (acknowledge, escalate, confirm, dismiss_fp, resolve)
* Action timeline
* Hides family-specific widgets when family_head is False
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="Incident Detail · NetSentinel",
    page_icon="🔍",
    layout="wide",
)

import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import (  # noqa: E402
    APIError,
    get_brief,
    get_incident,
    get_incidents,
    get_model_info,
    post_action,
)
from nscore.contracts.policy import (  # noqa: E402
    NOVELTY_BONUS,
    burst_factor,
    confidence_band,
)
from nscore.contracts.schemas import (  # noqa: E402
    ActionType,
    AnalystActionIn,
    AnalystActionRecord,
    IncidentStatus,
    Verdict,
)

theme.inject_css()
theme.render_api_down_banner()
theme.render_full_sidebar()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fmt_dt(val: Any) -> str:
    """Format datetime or string nicely."""
    try:
        return val.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(val)


def _format_shift(val: float, baseline: float | None) -> str:
    """Compute human-readable difference against benign baseline."""
    if baseline is None:
        return "No baseline"
    if baseline == 0.0:
        if val == 0.0:
            return "Matches normal (0.0)"
        return f"+{val:g} above baseline (0.0)"
    if val == baseline:
        return "Matches normal"

    ratio = val / baseline
    if ratio >= 2.0:
        return f"{ratio:,.1f}× higher than normal"
    if 0.0 < ratio <= 0.5:
        inv = baseline / val if val != 0 else 0
        return f"{inv:,.1f}× lower than normal"

    pct = ((val - baseline) / baseline) * 100.0
    prefix = "+" if pct > 0 else ""
    return f"{prefix}{pct:.1f}% vs normal"


def _build_shap_chart(top_features: list[Any]) -> go.Figure:
    """Horizontal bar chart of SHAP values sorted by magnitude."""
    sorted_features = sorted(top_features, key=lambda x: abs(x.shap_value))
    names = [f.feature for f in sorted_features]
    shap_vals = [f.shap_value for f in sorted_features]
    colors = [
        theme.CLR_HIGH if v >= 0 else theme.CLR_CONF_HIGH
        for v in shap_vals
    ]

    hover_text = [
        (
            f"<b>{f.feature}</b><br>"
            f"SHAP Impact: {f.shap_value:+.3f}<br>"
            f"Observed: {f.value:g}<br>"
            f"Baseline: {f.baseline_median if f.baseline_median is not None else 'N/A'}"
        )
        for f in sorted_features
    ]

    fig = go.Figure(
        go.Bar(
            x=shap_vals,
            y=names,
            orientation="h",
            marker=dict(
                color=colors,
                line=dict(color=theme.BORDER_SUBTLE, width=1),
            ),
            hoverinfo="text",
            hovertext=hover_text,
        )
    )

    fig.update_layout(
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme.TXT_PRIMARY, family=theme.FONT_SANS),
        xaxis=dict(
            title="SHAP Value (Impact on Attack Score)",
            gridcolor=theme.BORDER_SUBTLE,
            zerolinecolor=theme.BORDER_SUBTLE,
        ),
        yaxis=dict(gridcolor=theme.BORDER_SUBTLE),
        height=260,
    )
    return fig


# ---------------------------------------------------------------------------
# Load model & incident
# ---------------------------------------------------------------------------

try:
    model_info = get_model_info()
    family_head_enabled = model_info.family_head
except APIError:
    family_head_enabled = True
    model_info = None

# Top bar navigation & selector
col_nav, col_select = st.columns([1, 2])
with col_nav:
    if st.button("← Back to Live Queue", use_container_width=True, key="_btn_back_queue"):
        st.switch_page("pages/1_Live_Queue.py")

# Fetch available incidents for selector dropdown
available_ids = ["INC-1002"]
try:
    recent_page = get_incidents(limit=25)
    if recent_page.items:
        available_ids = [i.incident_id for i in recent_page.items]
except Exception:
    pass

selected_id = st.session_state.get("selected_incident_id", available_ids[0])
if selected_id not in available_ids:
    available_ids = [selected_id] + available_ids

with col_select:
    target_id = st.selectbox(
        "Select Incident",
        available_ids,
        index=available_ids.index(selected_id),
        key="_incident_selector",
        label_visibility="collapsed",
    )
    if target_id != selected_id:
        st.session_state["selected_incident_id"] = target_id
        st.rerun()

current_incident_id = target_id

try:
    detail = get_incident(current_incident_id)
except APIError as exc:
    st.markdown(
        theme.error_state(
            f"Could Not Load Incident {current_incident_id}",
            str(exc),
            "Verify incident ID exists in the queue or verify backend API connectivity.",
        ),
        unsafe_allow_html=True,
    )
    st.stop()

# Support live status override in session state
status_key = f"_status_override_{detail.incident_id}"
current_status_val = st.session_state.get(status_key, detail.status.value)


# ---------------------------------------------------------------------------
# Hero Header
# ---------------------------------------------------------------------------

st.markdown(
    f"<div style='display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin:12px 0;'>"
    f"<h1 style='margin:0;font-size:2.2rem;font-family:{theme.FONT_MONO};'>{detail.incident_id}</h1>"
    f"<div>{theme.risk_score_html(detail.risk_score, detail.risk_level)}&nbsp;"
    f"{theme.risk_badge(detail.risk_level)}</div>"
    f"<div>{theme.verdict_chip(detail.verdict.value)}</div>"
    f"<div>{theme.status_pill(current_status_val)}</div>"
    f"{(theme.family_tag(detail.attack_family.value) if family_head_enabled else '')}"
    f"{(theme.mitre_badge(detail.mitre_technique_id, detail.mitre_technique_name) if family_head_enabled else '')}"
    f"</div>",
    unsafe_allow_html=True,
)

if not family_head_enabled:
    st.info(
        "ℹ️ Binary-only bundle active (LUFlow schema) — "
        "attack type classification and MITRE mappings are hidden.",
        icon="ℹ️",
    )

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Risk Breakdown (confidence × severity × burst = score)
# ---------------------------------------------------------------------------

st.subheader("🎯 Risk Engine Breakdown")

burst = burst_factor(detail.flow_count)
is_novel = detail.verdict == Verdict.NOVEL_ANOMALY
novel_bonus_val = NOVELTY_BONUS if is_novel else 0.0

col_c1, col_c2, col_c3, col_c4, col_c5 = st.columns(5)
with col_c1:
    conf_band = confidence_band(detail.max_confidence)
    st.metric("Max Confidence", f"{detail.max_confidence:.2f}")
    st.markdown(theme.confidence_badge(conf_band), unsafe_allow_html=True)

with col_c2:
    st.metric("Expected Severity", f"{detail.severity:.2f}")
    st.caption("Consequence weight (0–1)")

with col_c3:
    st.metric("Burst Factor", f"{burst:.3f}×")
    st.caption(f"{detail.flow_count:,} flow{'s' if detail.flow_count != 1 else ''}")

with col_c4:
    bonus_str = f"+{novel_bonus_val:.2f}" if is_novel else "0.00"
    st.metric("Novelty Bonus", bonus_str)
    st.caption("Novel anomaly bonus (+0.10)" if is_novel else "Known attack / benign (none)")

with col_c5:
    st.metric("Final Risk Score", f"{detail.risk_score} / 100")
    st.markdown(theme.risk_badge(detail.risk_level), unsafe_allow_html=True)

bonus_term = f" + {novel_bonus_val:.2f} (Novelty)" if is_novel else ""
st.markdown(
    f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
    f"border-radius:6px;padding:8px 14px;font-size:0.84rem;color:{theme.TXT_SECONDARY};margin:8px 0;'>"
    f"<b>Formula:</b> <code>round(100 × (Confidence [{detail.max_confidence:.2f}] × "
    f"Severity [{detail.severity:.2f}] × Burst [{burst:.3f}]{bonus_term}))</code> = "
    f"<strong style='color:{theme.TXT_PRIMARY};'>{detail.risk_score}</strong> ({detail.risk_level})"
    f"</div>",
    unsafe_allow_html=True,
)

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Metadata & Sample Flow IDs
# ---------------------------------------------------------------------------

col_meta1, col_meta2 = st.columns([1, 1])
with col_meta1:
    st.subheader("🌐 Network Endpoints")
    st.markdown(
        f"- **Source Host:** `{detail.src_ip}`\n"
        f"- **Destination Host:** `{detail.dst_ip}:{detail.dst_port}`\n"
        f"- **Model Version:** `{detail.model_version}`\n"
        f"- **Flow Count:** `{detail.flow_count:,}`"
    )

with col_meta2:
    st.subheader("⏱️ Activity Window")
    st.markdown(
        f"- **First Seen:** `{_fmt_dt(detail.first_seen)}`\n"
        f"- **Last Seen:** `{_fmt_dt(detail.last_seen)}`\n"
        f"- **Status:** {theme.status_pill(current_status_val)}\n"
        f"- **Verdict:** {theme.verdict_chip(detail.verdict.value)}",
        unsafe_allow_html=True,
    )

if detail.sample_flow_ids:
    flow_badges = " ".join([f"`{fid}`" for fid in detail.sample_flow_ids])
    st.markdown(f"**Sample Flow IDs ({len(detail.sample_flow_ids)}):** {flow_badges}")

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# SHAP Bar Chart & "vs-Normal" Table
# ---------------------------------------------------------------------------

st.subheader("🔬 Feature Attribution (SHAP) & Baseline Comparison")
st.caption(
    "Top features driving the attack classification. "
    "SHAP explains why the flow was flagged; it does not alter the risk score."
)

if detail.top_features:
    col_chart, col_table = st.columns([1, 1])

    with col_chart:
        st.markdown("**SHAP Feature Impact**")
        fig = _build_shap_chart(detail.top_features)
        st.plotly_chart(fig, use_container_width=True)

    with col_table:
        st.markdown("**'vs Normal' Baseline Comparison**")
        rows = []
        for feat in detail.top_features:
            rows.append({
                "Feature": feat.feature,
                "Observed": f"{feat.value:g}",
                "Normal Median": (
                    f"{feat.baseline_median:g}"
                    if feat.baseline_median is not None
                    else "—"
                ),
                "Observed vs Normal": _format_shift(feat.value, feat.baseline_median),
                "SHAP": f"{feat.shap_value:+.3f}",
            })
        df_vs_normal = pd.DataFrame(rows)
        st.dataframe(df_vs_normal, use_container_width=True, hide_index=True)
else:
    st.markdown(
        theme.empty_state(
            "🔬",
            "No SHAP Feature Attribution",
            "Feature attribution scores were not calculated for this incident.",
        ),
        unsafe_allow_html=True,
    )

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Brief Panel (LLM / Template)
# ---------------------------------------------------------------------------

st.subheader("📝 SOC Incident Brief")

brief_session_key = f"_brief_cache_{detail.incident_id}"
active_brief = st.session_state.get(brief_session_key, detail.brief)

col_brief_hdr, col_brief_btn = st.columns([3, 1])
with col_brief_hdr:
    if active_brief:
        source_label = "Azure OpenAI" if active_brief.source == "azure_openai" else "Deterministic Template"
        badge_color = "#1565C0" if active_brief.source == "azure_openai" else "#78909C"
        source_badge = (
            f'<span style="background:{badge_color};color:#fff;font-size:0.70rem;'
            f'font-weight:700;padding:2px 8px;border-radius:4px;">{source_label}</span>'
        )
        conf_pill = theme.confidence_badge(active_brief.confidence_band)
        gen_time = _fmt_dt(active_brief.generated_at)
        st.markdown(
            f"Source: {source_badge} &nbsp;|&nbsp; "
            f"Confidence: {conf_pill} &nbsp;|&nbsp; "
            f"<span style='color:{theme.TXT_MUTED};font-size:0.8rem;'>Generated: {gen_time}</span>",
            unsafe_allow_html=True,
        )

with col_brief_btn:
    if st.button("🔄 Regenerate Brief", use_container_width=True, key="_btn_regen_brief"):
        with st.spinner("Generating brief via LLM / template fallback..."):
            try:
                fresh_brief = get_brief(detail.incident_id, refresh=True)
                st.session_state[brief_session_key] = fresh_brief
                st.success("Brief refreshed!")
                st.rerun()
            except APIError as err:
                st.error(f"Failed to generate brief: {err}")

if active_brief:
    st.markdown(
        f"<div style='background:{theme.BG_CARD};border-left:4px solid {theme.CLR_HIGH};"
        f"border-top:1px solid {theme.BORDER_SUBTLE};border-right:1px solid {theme.BORDER_SUBTLE};"
        f"border-bottom:1px solid {theme.BORDER_SUBTLE};border-radius:0 8px 8px 0;"
        f"padding:16px 20px;font-size:0.95rem;line-height:1.6;color:{theme.TXT_PRIMARY};'>"
        f"{active_brief.text}"
        f"</div>",
        unsafe_allow_html=True,
    )
else:
    st.warning("No brief currently generated for this incident. Click 'Regenerate Brief' above.")

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Analyst Actions & Audit Timeline
# ---------------------------------------------------------------------------

st.subheader("⚡ Analyst Actions")

analyst_name, analyst_role, x_analyst_header = theme.get_analyst()

st.markdown(
    f"<div style='display:flex;align-items:center;gap:10px;margin-bottom:8px;'>"
    f"<span>Acting as:</span> {theme.analyst_badge(analyst_name, analyst_role)} "
    f"<span style='color:{theme.TXT_MUTED};font-size:0.80rem;font-family:{theme.FONT_MONO};'>"
    f"Header: <code>X-Analyst: {x_analyst_header}</code></span>"
    f"</div>",
    unsafe_allow_html=True,
)

action_note = st.text_input(
    "Analyst Note",
    placeholder="Enter triage notes, investigation remarks, or rationale...",
    key=f"_action_note_{detail.incident_id}",
)

btn_c1, btn_c2, btn_c3, btn_c4, btn_c5 = st.columns(5)

actions_store_key = f"_extra_actions_{detail.incident_id}"
extra_actions: list[AnalystActionRecord] = st.session_state.setdefault(actions_store_key, [])


def _record_action(action_type: ActionType, new_status: IncidentStatus) -> None:
    """Submit action to API client, update state, and refresh."""
    try:
        req = AnalystActionIn(action=action_type, note=action_note.strip() or None)
        rec = post_action(detail.incident_id, req, analyst=x_analyst_header)
        extra_actions.append(rec)
        st.session_state.setdefault("_global_analyst_actions", []).append(rec)
        st.session_state[status_key] = new_status.value
        st.success(f"Action '{action_type.value}' recorded by {x_analyst_header}!")
        st.rerun()
    except APIError as e:
        st.error(f"Action submission failed: {e}")


with btn_c1:
    if st.button("👁️ Acknowledge", use_container_width=True, key="_act_ack"):
        _record_action(ActionType.ACKNOWLEDGE, IncidentStatus.ACKNOWLEDGED)

with btn_c2:
    if st.button("🚀 Escalate", use_container_width=True, key="_act_esc"):
        _record_action(ActionType.ESCALATE, IncidentStatus.ESCALATED)

with btn_c3:
    if st.button("✅ Confirm TP", use_container_width=True, key="_act_conf"):
        _record_action(ActionType.CONFIRM, IncidentStatus.ACKNOWLEDGED)

with btn_c4:
    if st.button("🚫 Dismiss as FP", use_container_width=True, key="_act_fp"):
        _record_action(ActionType.DISMISS_FP, IncidentStatus.DISMISSED_FP)

with btn_c5:
    if st.button("🏁 Resolve", use_container_width=True, key="_act_res"):
        _record_action(ActionType.RESOLVE, IncidentStatus.RESOLVED)

st.markdown("#### 📜 Action Timeline")

all_actions = list(detail.actions) + extra_actions
if all_actions:
    for act in sorted(all_actions, key=lambda a: a.at, reverse=True):
        note_display = f"<br><em>\"{act.note}\"</em>" if act.note else ""
        pill_html = theme.status_pill(act.action.value)
        st.markdown(
            f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
            f"border-radius:6px;padding:10px 14px;margin-bottom:8px;font-size:0.86rem;'>"
            f"<strong>{act.analyst}</strong> &nbsp; {pill_html} &nbsp; "
            f"<span style='color:{theme.TXT_MUTED};font-size:0.78rem;'>{_fmt_dt(act.at)}</span>"
            f"{note_display}"
            f"</div>",
            unsafe_allow_html=True,
        )
else:
    st.markdown(
        theme.empty_state(
            "📜",
            "No Actions Recorded Yet",
            "No triage actions have been submitted for this incident. Use the action buttons above "
            "to acknowledge, escalate, or resolve.",
        ),
        unsafe_allow_html=True,
    )
