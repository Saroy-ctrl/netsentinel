"""NetSentinel SOC Dashboard — entry point.

Run with:
    streamlit run dashboard/app.py

Environment:
    NS_OFFLINE=1          read nscore/contracts/fixtures/ directly (default if nothing set)
    NS_API_URL=http://…   live or mock (NS_MOCK=1) FastAPI backend
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import streamlit as st

# ── make sure the repo root is on sys.path so `nscore` is importable ──────────
_REPO_ROOT = Path(__file__).parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ── page config (must be the first Streamlit call) ─────────────────────────────
st.set_page_config(
    page_title="NetSentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── late import (after path fix) ───────────────────────────────────────────────
from dashboard.api_client import APIError, data_source_label, get_live_metrics, get_model_info  # noqa: E402

# ---------------------------------------------------------------------------
# Sidebar — analyst sign-in + data-source badge
# ---------------------------------------------------------------------------

with st.sidebar:
    st.image(
        "https://img.shields.io/badge/NetSentinel-SOC%20Console-0d6efd?style=for-the-badge",
        use_container_width=True,
    )
    st.markdown("---")

    # Analyst sign-in (M4-05 will expand this; stub here so the state key exists)
    if "analyst_name" not in st.session_state:
        st.session_state["analyst_name"] = ""
    if "analyst_role" not in st.session_state:
        st.session_state["analyst_role"] = "SOC Analyst"

    with st.expander("👤 Analyst", expanded=st.session_state["analyst_name"] == ""):
        st.session_state["analyst_name"] = st.text_input(
            "Name",
            value=st.session_state["analyst_name"],
            placeholder="e.g. Asha Patel",
            key="_analyst_name_input",
        )
        st.session_state["analyst_role"] = st.selectbox(
            "Role",
            ["SOC Analyst", "Tier-2 Analyst", "Incident Responder", "Manager"],
            index=["SOC Analyst", "Tier-2 Analyst", "Incident Responder", "Manager"].index(
                st.session_state["analyst_role"]
            ),
            key="_analyst_role_select",
        )

    st.markdown("---")

    # Live header metrics in sidebar
    try:
        metrics = get_live_metrics()
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Open", metrics.incidents_open)
            st.metric("HIGH", metrics.incidents_by_level.get("HIGH", 0))
        with col2:
            st.metric("flows/s", f"{metrics.flows_per_sec_1m:.0f}")
            st.metric("MEDIUM", metrics.incidents_by_level.get("MEDIUM", 0))
    except APIError as e:
        st.warning(f"⚠️ Metrics unavailable: {e}")

    st.markdown("---")

    # Model info badge
    try:
        model = get_model_info()
        bundle_label = "2018" if model.feature_schema == "cic" else "LUFlow"
        schema_color = "blue" if model.feature_schema == "cic" else "green"
        st.markdown(
            f"**Bundle:** `{model.model_version}`  \n"
            f"**Schema:** :{schema_color}[{bundle_label}]  \n"
            f"**family_head:** {'✅' if model.family_head else '❌'}"
        )
    except APIError as e:
        st.warning(f"⚠️ Model info unavailable: {e}")

    st.markdown("---")
    st.caption(f"Data source: **{data_source_label()}**")
    st.caption("Contract v2.1.0")

# ---------------------------------------------------------------------------
# Main landing page
# ---------------------------------------------------------------------------

st.title("🛡️ NetSentinel — SOC Console")
st.markdown(
    """
Welcome to the **NetSentinel SOC Console**.

Use the **sidebar** to navigate between pages:

| Page | Description |
|---|---|
| 📋 **Live Queue** | Incidents sorted by risk score — auto-refreshes every 3 s |
| 🔍 **Incident Detail** | Risk breakdown · SHAP · MITRE · analyst actions |
| 📊 **Model & Evaluation** | Per-class metrics · LOAO · real-world (LUFlow) |
| 📡 **Drift & Health** | PSI bars · status banner · throughput · latency |
| 📈 **Analyst Metrics** | Confirmed precision · FP rate · MTTA |
"""
)

# API-down banner (M4-10 polish; already scaffolded here)
if os.environ.get("NS_OFFLINE", "").strip().lower() not in ("1", "true", "yes"):
    try:
        from dashboard.api_client import health_check

        health_check()
    except APIError:
        st.error(
            "⛔ **API is unreachable.** "
            "Set `NS_OFFLINE=1` to run from fixtures, "
            "or check that the backend is running at `NS_API_URL`.",
            icon="⛔",
        )
