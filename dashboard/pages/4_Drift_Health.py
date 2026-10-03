"""Drift & Health page stub — implemented in M4-07."""
import streamlit as st

st.set_page_config(page_title="Drift & Health · NetSentinel", page_icon="📡", layout="wide")
st.title("📡 Drift & Health")
st.info("Full implementation in M4-07.")

from dashboard.api_client import APIError, get_drift, get_live_metrics  # noqa: E402

try:
    drift = get_drift()
    st.write(f"**Drift status:** `{drift.status}` | **Max PSI:** {drift.max_psi:.3f} | **Window:** {drift.window_size} flows")
    metrics = get_live_metrics()
    st.write(f"**Flows/s:** {metrics.flows_per_sec_1m:.1f} | **p50:** {metrics.latency_ms_p50} ms | **p95:** {metrics.latency_ms_p95} ms")
except APIError as e:
    st.error(f"Could not load drift data: {e}")
