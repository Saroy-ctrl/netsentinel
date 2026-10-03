"""Incident Detail page stub — implemented in M4-04."""
import streamlit as st

st.set_page_config(page_title="Incident Detail · NetSentinel", page_icon="🔍", layout="wide")

import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import APIError, get_incident  # noqa: E402

theme.inject_css()

st.title("🔍 Incident Detail")
st.info("Full implementation in M4-04. Select an incident from the Live Queue.")

# If an incident_id was passed via session state (set by M4-03 queue), show it.
incident_id = st.session_state.get("selected_incident_id", "INC-1002")
st.write(f"Showing fixture for incident: **{incident_id}**")

try:
    detail = get_incident(incident_id)
    # Show themed header badges as a preview of the M4-04 layout
    st.markdown(
        theme.risk_badge(detail.risk_level)
        + " &nbsp; "
        + theme.verdict_chip(detail.verdict.value)
        + " &nbsp; "
        + theme.status_pill(detail.status.value)
        + " &nbsp; "
        + theme.mitre_badge(detail.mitre_technique_id, detail.mitre_technique_name),
        unsafe_allow_html=True,
    )
    st.json(detail.model_dump(mode="json"), expanded=False)
except APIError as e:
    st.error(f"Could not load incident: {e}")
