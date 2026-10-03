"""Analyst Metrics page stub — implemented in M4-08."""
import streamlit as st

st.set_page_config(page_title="Analyst Metrics · NetSentinel", page_icon="📈", layout="wide")
st.title("📈 Analyst Metrics")
st.info("Full implementation in M4-08.")

from dashboard.api_client import APIError, get_live_metrics  # noqa: E402

try:
    m = get_live_metrics()
    prec = f"{m.analyst_confirmed_precision:.1%}" if m.analyst_confirmed_precision is not None else "—"
    fp_rate = f"{m.fp_dismiss_rate:.1%}" if m.fp_dismiss_rate is not None else "—"
    mtta = f"{m.mtta_seconds:.0f} s" if m.mtta_seconds is not None else "—"
    st.write(f"**Confirmed precision:** {prec}")
    st.write(f"**FP dismiss rate:** {fp_rate}")
    st.write(f"**MTTA:** {mtta}")
except APIError as e:
    st.error(f"Could not load metrics: {e}")
