"""Incident Detail page stub — implemented in M4-04."""
import streamlit as st

st.set_page_config(page_title="Incident Detail · NetSentinel", page_icon="🔍", layout="wide")
st.title("🔍 Incident Detail")
st.info("Full implementation in M4-04. Select an incident from the Live Queue.")

from dashboard.api_client import APIError, get_incident  # noqa: E402

# If an incident_id was passed via session state (set by M4-03 queue), show it.
incident_id = st.session_state.get("selected_incident_id", "INC-1002")
st.write(f"Showing fixture for incident: **{incident_id}**")

try:
    detail = get_incident(incident_id)
    st.json(detail.model_dump(mode="json"), expanded=False)
except APIError as e:
    st.error(f"Could not load incident: {e}")
