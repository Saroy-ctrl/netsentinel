"""Live Queue — M4-03.

Features
--------
* Incidents sorted by risk score (descending) — always
* Filter bar: status · verdict · family · level
* Header counters: open HIGHs · novel anomalies · flows/sec
* Loaded-bundle badge (2018 / LUFlow) pulled from /v1/model
* 3-second auto-refresh via st.fragment(run_every=3)
* New-row flash animation for rows that appeared since the last refresh
* Pagination: page-size selector + Prev/Next for 500+ incident lists
* Click row → sets session_state["selected_incident_id"] for Incident Detail page
"""

from __future__ import annotations

import streamlit as st

st.set_page_config(
    page_title="Live Queue · NetSentinel",
    page_icon="📋",
    layout="wide",
)

import dashboard.theme as theme  # noqa: E402
from dashboard.api_client import APIError, get_incidents, get_live_metrics, get_model_info  # noqa: E402
from nscore.contracts.schemas import AttackFamily, IncidentStatus, Verdict  # noqa: E402

theme.inject_css()
theme.render_api_down_banner()
theme.render_full_sidebar()

# ── session-state defaults ────────────────────────────────────────────────────
_DEFAULTS: dict[str, object] = {
    "selected_incident_id": None,
    "lq_status": "",
    "lq_verdict": "",
    "lq_family": "",
    "lq_level": "",
    "lq_page": 0,
    "lq_page_size": 25,
    # set of incident IDs seen on the previous refresh — used for new-row flash
    "lq_prev_ids": set(),
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


# ── filter options (from contract enums) ─────────────────────────────────────
_STATUS_OPTS = [""] + [s.value for s in IncidentStatus]
_VERDICT_OPTS = [""] + [v.value for v in Verdict if v != Verdict.BENIGN]
_FAMILY_OPTS = [""] + [
    f.value for f in AttackFamily
    if f not in (AttackFamily.BENIGN, AttackFamily.PORTSCAN)
]
_LEVEL_OPTS = ["", "HIGH", "MEDIUM", "LOW"]
_CLOSED = ("resolved", "dismissed_fp")  # statuses that no longer count as open
_PAGE_SIZES = [10, 25, 50, 100]

# ── helpers ───────────────────────────────────────────────────────────────────


def _fmt_time(dt: object) -> str:
    """Format a datetime as HH:MM:SS UTC for compact display."""
    try:
        return dt.strftime("%H:%M:%S")  # type: ignore[union-attr]
    except Exception:
        return str(dt)


def _render_header_counters() -> None:
    """Render the three KPI tiles at the top of the page."""
    try:
        metrics = get_live_metrics()
        high_open = metrics.incidents_by_level.get("HIGH", 0)
        novel_page = get_incidents(verdict="novel_anomaly", limit=500)
        novel_open = sum(1 for i in novel_page.items if str(getattr(i.status, "value", i.status)) not in _CLOSED)
    except APIError:
        high_open, novel_open = "—", "—"
        metrics = None

    try:
        model = get_model_info()
        bundle_html = theme.bundle_badge(model.feature_schema, model.model_version)
        family_head = model.family_head
    except APIError:
        bundle_html = "<span>bundle unavailable</span>"
        family_head = True

    c1, c2, c3, c4 = st.columns([1, 1, 1, 2])
    with c1:
        st.markdown(
            f"<div style='font-size:0.78rem;color:{theme.TXT_SECONDARY}'>Open HIGHs</div>"
            f"<div style='font-size:2rem;font-weight:800;color:{theme.CLR_HIGH}'>"
            f"{high_open}</div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"<div style='font-size:0.78rem;color:{theme.TXT_SECONDARY}'>Novel anomalies</div>"
            f"<div style='font-size:2rem;font-weight:800;color:{theme.CLR_NOVEL_ANOMALY}'>"
            f"{novel_open}</div>",
            unsafe_allow_html=True,
        )
    with c3:
        fps = f"{metrics.flows_per_sec_1m:.0f}" if metrics else "—"
        st.markdown(
            f"<div style='font-size:0.78rem;color:{theme.TXT_SECONDARY}'>Flows / sec</div>"
            f"<div style='font-size:2rem;font-weight:800;color:{theme.TXT_PRIMARY}'>"
            f"{fps}</div>",
            unsafe_allow_html=True,
        )
    with c4:
        fh_note = "" if family_head else "&nbsp;·&nbsp;no family head (LUFlow bundle)"
        st.markdown(
            f"<div style='font-size:0.78rem;color:{theme.TXT_SECONDARY};margin-bottom:4px'>"
            f"Loaded bundle</div>"
            f"{bundle_html}{fh_note}",
            unsafe_allow_html=True,
        )


def _render_filters() -> tuple[str, str, str, str]:
    """Render the filter widgets and return (status, verdict, family, level)."""
    st.markdown(theme.divider(), unsafe_allow_html=True)
    fc1, fc2, fc3, fc4, fc5 = st.columns([2, 2, 2, 2, 1])
    with fc1:
        status = st.selectbox(
            "Status",
            _STATUS_OPTS,
            index=_STATUS_OPTS.index(st.session_state["lq_status"])
            if st.session_state["lq_status"] in _STATUS_OPTS else 0,
            key="_lq_status_sel",
            format_func=lambda x: x or "All statuses",
        )
    with fc2:
        verdict = st.selectbox(
            "Verdict",
            _VERDICT_OPTS,
            index=_VERDICT_OPTS.index(st.session_state["lq_verdict"])
            if st.session_state["lq_verdict"] in _VERDICT_OPTS else 0,
            key="_lq_verdict_sel",
            format_func=lambda x: x.replace("_", " ").title() if x else "All verdicts",
        )
    with fc3:
        family = st.selectbox(
            "Family",
            _FAMILY_OPTS,
            index=_FAMILY_OPTS.index(st.session_state["lq_family"])
            if st.session_state["lq_family"] in _FAMILY_OPTS else 0,
            key="_lq_family_sel",
            format_func=lambda x: x or "All families",
        )
    with fc4:
        level = st.selectbox(
            "Level",
            _LEVEL_OPTS,
            index=_LEVEL_OPTS.index(st.session_state["lq_level"])
            if st.session_state["lq_level"] in _LEVEL_OPTS else 0,
            key="_lq_level_sel",
            format_func=lambda x: x or "All levels",
        )
    with fc5:
        if st.button("Clear", width="stretch", key="_lq_clear"):
            st.session_state["lq_status"] = ""
            st.session_state["lq_verdict"] = ""
            st.session_state["lq_family"] = ""
            st.session_state["lq_level"] = ""
            st.session_state["lq_page"] = 0
            st.rerun()

    # Persist filter choices so they survive the 3 s auto-refresh
    st.session_state["lq_status"] = status
    st.session_state["lq_verdict"] = verdict
    st.session_state["lq_family"] = family
    st.session_state["lq_level"] = level

    return status, verdict, family, level


def _incident_row_html(inc: object, is_new: bool) -> str:
    """Build the HTML for one incident card row."""
    card_lvl = theme.card_css_class(inc.risk_level)  # type: ignore[attr-defined]
    flash = " ns-card-new-flash" if is_new else ""

    badge = theme.risk_badge(inc.risk_level)  # type: ignore[attr-defined]
    score = theme.risk_score_html(inc.risk_score, inc.risk_level)  # type: ignore[attr-defined]
    chip = theme.verdict_chip(inc.verdict.value)  # type: ignore[attr-defined]
    pill = theme.status_pill(inc.status.value)  # type: ignore[attr-defined]
    ftag = theme.family_tag(inc.attack_family.value)  # type: ignore[attr-defined]
    mitre = theme.mitre_badge(
        inc.mitre_technique_id,  # type: ignore[attr-defined]
        inc.mitre_technique_name,  # type: ignore[attr-defined]
    )

    ts_first = _fmt_time(inc.first_seen)  # type: ignore[attr-defined]
    ts_last = _fmt_time(inc.last_seen)  # type: ignore[attr-defined]

    return f"""
<div class="ns-card {card_lvl}{flash}" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
  <div style="min-width:100px">{score}&nbsp;{badge}</div>
  <div style="min-width:140px">{chip}</div>
  <div style="min-width:100px">{pill}</div>
  <div style="min-width:90px">{ftag}</div>
  <div style="flex:1;min-width:120px">
    <span class="ns-mono" style="font-size:0.82rem">{inc.incident_id}</span>
    &nbsp;<span class="ns-muted">{inc.src_ip} → {inc.dst_ip}:{inc.dst_port}</span>
  </div>
  <div style="min-width:100px;text-align:right">
    <span class="ns-muted" style="font-size:0.75rem">
      {inc.flow_count:,} flow{'s' if inc.flow_count != 1 else ''}<br>
      {ts_first} – {ts_last}
    </span>
  </div>
  {'<div>' + mitre + '</div>' if mitre else ''}
</div>
"""


def _render_table_header() -> None:
    """Static column-header row above the incident cards."""
    st.markdown(
        f"<div style='display:flex;gap:10px;padding:4px 16px;"
        f"font-size:0.70rem;font-weight:700;letter-spacing:0.06em;"
        f"text-transform:uppercase;color:{theme.TXT_MUTED};'>"
        f"<div style='min-width:100px'>Score</div>"
        f"<div style='min-width:140px'>Verdict</div>"
        f"<div style='min-width:100px'>Status</div>"
        f"<div style='min-width:90px'>Family</div>"
        f"<div style='flex:1;min-width:120px'>Incident / Endpoint</div>"
        f"<div style='min-width:100px;text-align:right'>Flows / Seen</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


def _render_pagination(total: int, page_size: int, page: int) -> tuple[int, int]:
    """Render Prev/Next controls; return updated (page, page_size)."""
    total_pages = max(1, (total + page_size - 1) // page_size)
    st.markdown(theme.divider(), unsafe_allow_html=True)
    pc1, pc2, pc3, pc4 = st.columns([1, 1, 2, 1])
    with pc1:
        if st.button("◀ Prev", disabled=page == 0, key="_lq_prev"):
            st.session_state["lq_page"] = max(0, page - 1)
            st.rerun()
    with pc2:
        if st.button("Next ▶", disabled=page >= total_pages - 1, key="_lq_next"):
            st.session_state["lq_page"] = min(total_pages - 1, page + 1)
            st.rerun()
    with pc3:
        st.markdown(
            f"<div style='padding-top:6px;color:{theme.TXT_SECONDARY};font-size:0.82rem'>"
            f"Page {page + 1} / {total_pages} &nbsp;·&nbsp; {total} incident(s)</div>",
            unsafe_allow_html=True,
        )
    with pc4:
        new_size = st.selectbox(
            "Per page",
            _PAGE_SIZES,
            index=_PAGE_SIZES.index(page_size) if page_size in _PAGE_SIZES else 1,
            key="_lq_page_size_sel",
            label_visibility="collapsed",
        )
        if new_size != page_size:
            st.session_state["lq_page_size"] = new_size
            st.session_state["lq_page"] = 0
            st.rerun()
    return st.session_state["lq_page"], st.session_state["lq_page_size"]


# ── page skeleton (outside fragment — renders once) ───────────────────────────

st.title("📋 Live Queue")

_render_header_counters()

status_f, verdict_f, family_f, level_f = _render_filters()


# ── auto-refreshing fragment ───────────────────────────────────────────────────

@st.fragment(run_every=3)
def _live_queue_fragment() -> None:
    """Renders the incident table.  Re-runs every 3 seconds automatically."""
    page_idx: int = st.session_state["lq_page"]
    page_size: int = st.session_state["lq_page_size"]
    prev_ids: set[str] = st.session_state["lq_prev_ids"]

    # ── fetch ────────────────────────────────────────────────────────────────
    try:
        result = get_incidents(
            status=status_f or None,
            verdict=verdict_f or None,
            family=family_f or None,
            level=level_f or None,
            limit=page_size,
            offset=page_idx * page_size,
        )
    except APIError as exc:
        st.markdown(
            theme.error_state(
                "Could Not Load Incidents",
                str(exc),
                "Check backend connectivity at NS_API_URL or verify if service is operational.",
            ),
            unsafe_allow_html=True,
        )
        return

    items = result.items
    total = result.total

    # ── empty state ──────────────────────────────────────────────────────────
    if total == 0:
        st.markdown(
            theme.empty_state(
                "🔍",
                "No Incidents Found",
                "No open incidents match the currently selected filter parameters. "
                "Try resetting filters or adjusting criteria above.",
            ),
            unsafe_allow_html=True,
        )
        if st.button("Reset All Filters", key="_btn_reset_filters_empty", width="stretch"):
            st.session_state["lq_status"] = ""
            st.session_state["lq_verdict"] = ""
            st.session_state["lq_family"] = ""
            st.session_state["lq_level"] = ""
            st.session_state["lq_page"] = 0
            st.rerun()
        st.session_state["lq_prev_ids"] = set()
        return

    # ── detect new rows (appeared since last refresh) ────────────────────────
    current_ids = {inc.incident_id for inc in items}
    new_ids = current_ids - prev_ids if prev_ids else set()
    st.session_state["lq_prev_ids"] = current_ids

    # ── column header ────────────────────────────────────────────────────────
    _render_table_header()

    # ── incident rows ────────────────────────────────────────────────────────
    for inc in items:
        is_new = inc.incident_id in new_ids
        row_html = _incident_row_html(inc, is_new)
        st.markdown(row_html, unsafe_allow_html=True)

        # Invisible button behind each row drives navigation to Incident Detail
        if st.button(
            f"Open {inc.incident_id}",
            key=f"_lq_open_{inc.incident_id}",
            help=f"Open detail for {inc.incident_id}",
            width="stretch",
        ):
            st.session_state["selected_incident_id"] = inc.incident_id
            st.switch_page("pages/2_Incident_Detail.py")

    # ── pagination controls ──────────────────────────────────────────────────
    _render_pagination(total, page_size, page_idx)


_live_queue_fragment()
