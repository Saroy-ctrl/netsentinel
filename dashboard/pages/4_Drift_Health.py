"""Drift & Health page stub — implemented in M4-07."""
import streamlit as st

st.set_page_config(page_title="Drift & Health · NetSentinel", page_icon="📡", layout="wide")

import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import APIError, get_drift, get_live_metrics  # noqa: E402

theme.inject_css()

st.title("📡 Drift & Health")
st.info("Full implementation in M4-07.")

try:
    drift = get_drift()
    # Show the themed drift status banner as a M4-07 preview
    st.markdown(theme.drift_status_banner(drift.status.value), unsafe_allow_html=True)
    st.write(
        f"**Max PSI:** {drift.max_psi:.3f} | "
        f"**Window:** {drift.window_size} flows"
    )
    metrics = get_live_metrics()
    st.write(
        f"**Flows/s:** {metrics.flows_per_sec_1m:.1f} | "
        f"**p50:** {metrics.latency_ms_p50} ms | "
        f"**p95:** {metrics.latency_ms_p95} ms"
    )
except APIError as e:
    st.error(f"Could not load drift data: {e}")
