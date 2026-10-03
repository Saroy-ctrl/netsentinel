"""Live Queue page stub — implemented in M4-03."""
import streamlit as st

st.set_page_config(page_title="Live Queue · NetSentinel", page_icon="📋", layout="wide")

import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import APIError, get_incidents  # noqa: E402

theme.inject_css()

st.title("📋 Live Queue")
st.info("Full implementation in M4-03. Data source is already wired — run `NS_OFFLINE=1` to see fixtures.")

try:
    page = get_incidents(limit=10)
    st.write(f"**{page.total}** incident(s) loaded.")
    for inc in page.items:
        badge = theme.risk_badge(inc.risk_level)
        chip = theme.verdict_chip(inc.verdict.value)
        pill = theme.status_pill(inc.status.value)
        st.markdown(
            f"{badge} &nbsp; {chip} &nbsp; {pill} &nbsp; "
            f'<span class="ns-mono">{inc.incident_id}</span> &nbsp; '
            f"{theme.family_tag(inc.attack_family.value)} &nbsp; "
            f'score <strong>{inc.risk_score}</strong>',
            unsafe_allow_html=True,
        )
except APIError as e:
    st.error(f"Could not load incidents: {e}")
