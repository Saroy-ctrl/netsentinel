"""Model & Evaluation page stub — implemented in M4-06."""
import streamlit as st

st.set_page_config(page_title="Model & Evaluation · NetSentinel", page_icon="📊", layout="wide")
st.title("📊 Model & Evaluation")
st.info("Full implementation in M4-06.")

from dashboard.api_client import APIError, get_evaluation, get_model_info  # noqa: E402

try:
    model = get_model_info()
    st.write(f"**Version:** `{model.model_version}` | **Registry:** `{model.bundle_ref}`")
    report = get_evaluation()
    st.write(f"**Macro F1:** {report.macro_f1:.3f} | **Binary ROC-AUC:** {report.binary_roc_auc:.3f}")
    st.write(f"**Benign FPR:** {report.benign_fpr:.4f} | **Classes:** {[label.value for label in report.labels]}")
except APIError as e:
    st.error(f"Could not load model info: {e}")
