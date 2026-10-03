"""Live Queue page stub — implemented in M4-03."""
import streamlit as st

st.set_page_config(page_title="Live Queue · NetSentinel", page_icon="📋", layout="wide")
st.title("📋 Live Queue")
st.info("Full implementation in M4-03. Data source is already wired — run `NS_OFFLINE=1` to see fixtures.")

from dashboard.api_client import APIError, get_incidents  # noqa: E402

try:
    page = get_incidents(limit=10)
    st.write(f"**{page.total}** incident(s) loaded from {page.total} total.")
    for inc in page.items:
        st.write(f"- `{inc.incident_id}` | {inc.risk_level} | {inc.attack_family} | score {inc.risk_score}")
except APIError as e:
    st.error(f"Could not load incidents: {e}")
