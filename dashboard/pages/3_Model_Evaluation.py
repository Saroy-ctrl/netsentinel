"""Model & Evaluation Page — M4-06.

Features
--------
* Model version, registry reference, dataset, and split metadata
* Operating FPR budget & calibrated thresholds
* Overall performance KPIs (Macro F1, ROC-AUC, PR-AUC, Benign FPR)
* Per-class metrics table (Precision, Recall, F1, FPR, Support, ROC-AUC)
* Interactive Confusion Matrix Heatmap (Plotly) — hidden when family_head is False
* Leave-One-Attack-Out (LOAO) grouped bar chart (Unseen Recall vs Seen Ceiling vs Novel Share)
* Real-World panel: LUFlow month-by-month temporal evaluation & label-free recalibration recovery
* Known Model Limitations & operational boundaries
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="Model & Evaluation · NetSentinel",
    page_icon="📊",
    layout="wide",
)

import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import APIError, get_evaluation, get_model_info  # noqa: E402

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


def _build_confusion_heatmap(
    labels: list[str], matrix: list[list[int]]
) -> go.Figure:
    """Build an annotated heatmap for the multi-class confusion matrix."""
    z_text = [[f"{val:,}" for val in row] for row in matrix]

    fig = go.Figure(
        data=go.Heatmap(
            z=matrix,
            x=labels,
            y=labels,
            text=z_text,
            texttemplate="%{text}",
            textfont=dict(size=11, color=theme.TXT_PRIMARY),
            colorscale="Viridis",
            showscale=True,
            colorbar=dict(title="Flows", tickfont=dict(color=theme.TXT_SECONDARY)),
        )
    )

    fig.update_layout(
        margin=dict(l=40, r=40, t=30, b=40),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme.TXT_PRIMARY, family=theme.FONT_SANS),
        xaxis=dict(
            title="Predicted Class",
            tickangle=-25,
            gridcolor=theme.BORDER_SUBTLE,
        ),
        yaxis=dict(
            title="True Class",
            autorange="reversed",
            gridcolor=theme.BORDER_SUBTLE,
        ),
        height=380,
    )
    return fig


def _build_loao_chart(loao_items: list[Any]) -> go.Figure:
    """Build grouped bar chart for LOAO zero-day generalization."""
    names = [item.held_out for item in loao_items]
    unseen_recalls = [item.recall for item in loao_items]
    seen_recalls = [item.seen_recall for item in loao_items]
    novel_shares = [item.novel_share for item in loao_items]

    # Error ranges if min/max available
    err_plus = [max(0.0, item.recall_max - item.recall) for item in loao_items]
    err_minus = [max(0.0, item.recall - item.recall_min) for item in loao_items]

    fig = go.Figure(
        data=[
            go.Bar(
                name="Held-Out Recall (Unseen)",
                x=names,
                y=unseen_recalls,
                marker=dict(color=theme.CLR_HIGH),
                error_y=dict(
                    type="data",
                    symmetric=False,
                    array=err_plus,
                    arrayminus=err_minus,
                    color=theme.TXT_SECONDARY,
                ),
                hovertemplate="<b>%{x}</b><br>Unseen Recall: %{y:.1%}<extra></extra>",
            ),
            go.Bar(
                name="Trained Ceiling (Seen)",
                x=names,
                y=seen_recalls,
                marker=dict(color="#1976D2"),
                hovertemplate="<b>%{x}</b><br>Seen Recall: %{y:.1%}<extra></extra>",
            ),
            go.Bar(
                name="Flagged as Novel Anomaly",
                x=names,
                y=novel_shares,
                marker=dict(color=theme.CLR_NOVEL_ANOMALY),
                hovertemplate="<b>%{x}</b><br>Novel Share: %{y:.1%}<extra></extra>",
            ),
        ]
    )

    fig.update_layout(
        barmode="group",
        margin=dict(l=10, r=10, t=20, b=30),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme.TXT_PRIMARY, family=theme.FONT_SANS),
        xaxis=dict(gridcolor=theme.BORDER_SUBTLE, tickfont=dict(size=11)),
        yaxis=dict(
            title="Recall / Share",
            tickformat=".0%",
            range=[0.0, 1.05],
            gridcolor=theme.BORDER_SUBTLE,
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(size=11),
        ),
        height=320,
    )
    return fig


# ---------------------------------------------------------------------------
# Data Fetching
# ---------------------------------------------------------------------------

try:
    model = get_model_info()
    report = get_evaluation()
except APIError as exc:
    st.markdown(
        theme.error_state(
            "Could Not Load Model Evaluation Data",
            str(exc),
            "Check that the model bundle is loaded or verify backend API connectivity.",
        ),
        unsafe_allow_html=True,
    )
    st.stop()


# ---------------------------------------------------------------------------
# Header & Registry Metadata
# ---------------------------------------------------------------------------

st.title("📊 Model & Evaluation")

col_badge, col_reg = st.columns([2, 3])
with col_badge:
    st.markdown(
        f"<div style='margin-bottom:8px;'>"
        f"<span style='font-size:1.4rem;font-weight:700;font-family:{theme.FONT_MONO};'>"
        f"{model.model_version}</span>&nbsp;&nbsp;"
        f"{theme.bundle_badge(model.feature_schema, model.model_version)}"
        f"</div>",
        unsafe_allow_html=True,
    )
with col_reg:
    reg_icon = "☁️" if model.registry == "azureml" else "📁"
    st.markdown(
        f"<div style='font-size:0.86rem;color:{theme.TXT_SECONDARY};line-height:1.6;'>"
        f"<strong>Registry Ref:</strong> <code>{model.bundle_ref}</code> ({reg_icon} {model.registry})<br>"
        f"<strong>Trained:</strong> {_fmt_ts(model.trained_at)} &nbsp;|&nbsp; "
        f"<strong>Features:</strong> {model.feature_count} features ({model.feature_schema.upper()} schema)"
        f"</div>",
        unsafe_allow_html=True,
    )

st.markdown(
    f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
    f"border-radius:6px;padding:10px 14px;margin-top:6px;font-size:0.84rem;color:{theme.TXT_SECONDARY};'>"
    f"<strong>Dataset:</strong> {model.dataset}<br>"
    f"<strong>Split Strategy:</strong> {model.split_strategy}"
    f"</div>",
    unsafe_allow_html=True,
)

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Operating FPR Budget & Headline Metrics
# ---------------------------------------------------------------------------

st.subheader("🎯 Operating Point & Benchmark Metrics")

c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.metric(
        "Operating Benign FPR",
        f"{report.benign_fpr:.2%}",
        delta=f"Target ≤ {model.operating_fpr_target:.2%}",
        delta_color="inverse",
    )
    st.caption("False alarm rate on the held-out TEST split (the budget is set on validation)")

with c2:
    st.metric("Macro F1", f"{report.macro_f1:.3f}")
    st.caption("Unweighted mean across all classes")

with c3:
    st.metric("Binary ROC-AUC", f"{report.binary_roc_auc:.3f}")
    st.caption("Attack vs Benign discrimination")

with c4:
    st.metric("Binary PR-AUC", f"{report.binary_pr_auc:.3f}")
    st.caption("Precision-Recall curve area")

with c5:
    tau_b = model.thresholds.get("tau_binary", 0.5)
    tau_f = model.thresholds.get("tau_family", 0.9)
    st.metric("Binary Gate (τ)", f"{tau_b:.2f}")
    st.caption(f"Family τ: {tau_f:.2f}")

st.markdown(
    f"<div style='background:{theme.BG_CARD};border-left:4px solid {theme.CLR_CONF_HIGH};"
    f"border-radius:0 6px 6px 0;padding:8px 14px;font-size:0.83rem;color:{theme.TXT_SECONDARY};margin:8px 0;'>"
    f"<strong>FPR Budget Calibration:</strong> NetSentinel thresholds are derived from a strict benign "
    f"false-alarm budget ({model.operating_fpr_target:.1%}), not arbitrary 0.5 cutoffs. At network scale "
    f"(~330k flows/hour), every 0.1% of false alarms translates to hundreds of spurious alerts. "
    f"Precision numbers are weighted to natural attack prevalence."
    f"</div>",
    unsafe_allow_html=True,
)

st.markdown(theme.divider(), unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Tabs for Deep Dives
# ---------------------------------------------------------------------------

tab_perclass, tab_loao, tab_realworld, tab_limits = st.tabs(
    [
        "📋 Per-Class & Confusion Matrix",
        "🛡️ Zero-Day Generalization (LOAO)",
        "🌐 Real-World Performance (LUFlow)",
        "⚠️ Limitations & Honesty",
    ]
)

# ── Tab 1: Per-Class & Confusion Matrix ───────────────────────────────────────
with tab_perclass:
    st.markdown("#### Per-Class Performance (CSE-CIC-IDS2018 Test Split)")

    col_tbl, col_cm = st.columns([1, 1])

    with col_tbl:
        st.markdown("**Per-Family Metrics Breakdown**")
        df_rows = []
        for pcm in report.per_class:
            auc_str = f"{pcm.roc_auc:.3f}" if pcm.roc_auc is not None else "—"
            df_rows.append(
                {
                    "Family": pcm.family.value,
                    "Precision": f"{pcm.precision:.1%}",
                    "Recall": f"{pcm.recall:.1%}",
                    "F1 Score": f"{pcm.f1:.3f}",
                    "FPR": f"{pcm.fpr:.2%}",
                    "Support": f"{pcm.support:,}",
                    "ROC-AUC": auc_str,
                }
            )
        st.dataframe(pd.DataFrame(df_rows), width="stretch", hide_index=True)
        st.caption(
            "All metrics measured on the purged time-blocked test split (60s session purge)."
        )

    with col_cm:
        if model.family_head:
            st.markdown("**Multi-Class Confusion Matrix**")
            label_names = [label.value for label in report.labels]
            fig_cm = _build_confusion_heatmap(label_names, report.confusion_matrix)
            st.plotly_chart(fig_cm, width="stretch")
        else:
            st.info(
                "ℹ️ Single-class bundle active (LUFlow schema) — "
                "multi-class confusion matrix is hidden because family_head is disabled.",
                icon="ℹ️",
            )


# ── Tab 2: Leave-One-Attack-Out (LOAO) ─────────────────────────────────────────
with tab_loao:
    st.markdown("#### Leave-One-Attack-Out (LOAO) Generalization")
    st.markdown(
        "NetSentinel tests zero-day generalization by deliberately withholding entire attack families "
        "or specific tools from both models during training, and evaluating recall on those unseen attacks "
        "at the fixed false-alarm budget (0.1% benign FPR)."
    )

    if report.loao:
        fig_loao = _build_loao_chart(report.loao)
        st.plotly_chart(fig_loao, width="stretch")

        st.markdown("**LOAO Detailed Results**")
        loao_table_rows = []
        for item in report.loao:
            range_str = f"{item.recall_min:.1%} – {item.recall_max:.1%}"
            loao_table_rows.append(
                {
                    "Held-Out Target": item.held_out,
                    "Kind": item.kind.title(),
                    "Flows": f"{item.n_flows:,}",
                    "Budget (FPR)": f"{item.budget:.2%}",
                    "Unseen Recall (Mean)": f"{item.recall:.1%}",
                    "Worst / Best Seed": range_str,
                    "Flagged Novel": f"{item.novel_share:.1%}",
                    "Seen Ceiling": f"{item.seen_recall:.1%}",
                }
            )
        st.dataframe(pd.DataFrame(loao_table_rows), width="stretch", hide_index=True)
        st.caption(
            "Key takeaway: unseen DoS tools are caught (~100%) and DoS/DDoS families mostly (79-85%); detections of "
            "unseen attacks are flagged as Novel Anomalies. Botnet is partial (66%, 51-76% across seeds), brute force "
            "is caught at this budget but fragile below it, and internal scans (Infiltration) and the LOIC-HTTP tool "
            "are missed (~1%). Ranges come from 3 seeds; see docs/model_card.md section 4."
        )
    else:
        st.info("No LOAO evaluation records present in this report.")


# ── Tab 3: Real-World Performance (LUFlow) ───────────────────────────────────
with tab_realworld:
    st.markdown("#### Real-World Traffic, Month by Month (LUFlow)")
    st.markdown(
        "LUFlow is live, unscripted internet traffic from Lancaster University honeypots. The model is trained on the "
        "first two months and then frozen; every later month is scored with it. **Drift (PSI) is a warning light**: "
        "it says the traffic changed, not that detection failed. *Recalibrated* = thresholds and the benign-only "
        "IsolationForest refit on a recent, unlabelled benign window; on this data it did not give a consistent gain."
    )

    rw_items = [e for e in report.external if e.dataset == "LUFlow"]
    tool_items = [e for e in report.external if e.protocol == "tool_holdout"]

    def _psi_label(psi: float | None) -> str:
        if psi is None:
            return "n/a"
        return f"{psi:.2f} ({'ALERT' if psi >= 0.25 else 'WATCH' if psi >= 0.10 else 'OK'})"

    if rw_items:
        by_period: dict[str, dict[str, Any]] = {}
        for e in rw_items:
            row = by_period.setdefault(e.period or "?", {"Month": e.period or "?"})
            if e.protocol == "real_world_temporal":
                row["Max PSI (status)"] = _psi_label(e.max_psi)
                row["Recall (frozen)"] = f"{e.binary_recall:.1%}"
                row["Benign FPR (frozen)"] = f"{e.benign_fpr:.2%}"
                row["Outliers flagged by IForest"] = f"{e.novel_recall:.0%}" if e.novel_recall is not None else "n/a"
            elif e.protocol == "real_world_recalibrated":
                row["Recall (recalibrated)"] = f"{e.binary_recall:.1%}"
                row["Benign FPR (recalibrated)"] = f"{e.benign_fpr:.2%}"
        st.dataframe(pd.DataFrame([by_period[k] for k in sorted(by_period)]), width="stretch", hide_index=True)
        st.caption("Source: the loaded bundle's evaluation report (docs/experiments.md §8). Shown when a LUFlow bundle "
                   "is loaded; the 2018 bundle has no LUFlow rows.")
    else:
        st.info("This bundle has no LUFlow results. Load `luflow-v1`, or see docs/experiments.md §8.")

    if tool_items:
        st.markdown("**Tool Holdout Studies (e.g. DDoS-HOIC)**")
        tool_rows = []
        for ti in tool_items:
            tool_rows.append(
                {
                    "Dataset": ti.dataset,
                    "Study": ti.protocol.replace("_", " ").title(),
                    "Recall": f"{ti.binary_recall:.1%}",
                    "Benign FPR": f"{ti.benign_fpr:.2%}",
                    "Novel Recall": f"{ti.novel_recall:.1%}" if ti.novel_recall else "—",
                    "Notes": ti.notes or "—",
                }
            )
        st.dataframe(pd.DataFrame(tool_rows), width="stretch", hide_index=True)


# ── Tab 4: Limitations & Honesty ──────────────────────────────────────────────
with tab_limits:
    st.markdown("#### Documented Model Limitations & Operational Boundaries")
    st.markdown(
        "In accordance with NetSentinel's **Honest by Default** architectural principle, "
        "known model limitations and failure modes are explicitly documented rather than concealed:"
    )

    if report.limitations:
        for limit in report.limitations:
            st.warning(f"⚠️ **Limitation:** {limit}")
    else:
        st.info("No explicit limitations registered.")

    st.markdown(
        f"<div style='background:{theme.BG_CARD};border:1px solid {theme.BORDER_SUBTLE};"
        f"border-radius:8px;padding:14px 18px;margin-top:10px;line-height:1.6;font-size:0.86rem;'>"
        f"<strong>Key Operational Disclaimers:</strong><br>"
        f"• <strong>Never Auto-Block:</strong> NetSentinel flags, correlates, and scores risk for human SOC analyst "
        f"triage. It does not automatically execute network blocks.<br>"
        f"• <strong>Adversarial Evasion:</strong> Packet pacing, subtle padding, and polymorphic command structures "
        f"can shift statistical flow signatures and reduce detection confidence.<br>"
        f"• <strong>Cross-Network Transfer:</strong> Features derived from one network topography (e.g. AWS 2018) "
        f"do not directly map to dissimilar enterprise networks without domain feature spec adaptation."
        f"</div>",
        unsafe_allow_html=True,
    )
