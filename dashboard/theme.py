"""NetSentinel SOC Dashboard — visual system (M4-02).

Single source of truth for every colour, CSS class, and HTML rendering helper
used across the dashboard.  Import this module in every page; never hard-code
colours or HTML badge markup in page files.

Usage
-----
    import dashboard.theme as theme

    theme.inject_css()                          # call once per page, before any st.* render calls
    st.markdown(theme.risk_badge("HIGH"), unsafe_allow_html=True)
    st.markdown(theme.verdict_chip("known_attack"), unsafe_allow_html=True)
    st.markdown(theme.status_pill("escalated"), unsafe_allow_html=True)

All public functions return an HTML string.  The caller passes it to
``st.markdown(..., unsafe_allow_html=True)`` or concatenates it into a larger
HTML block.  Nothing here calls ``st.`` directly — this keeps the module
testable without a Streamlit context.
"""

from __future__ import annotations

import streamlit as st

# ---------------------------------------------------------------------------
# Colour tokens — the only place these hex values should appear in the codebase
# ---------------------------------------------------------------------------

# Risk-level palette (SOC convention: red / amber / grey)
CLR_HIGH = "#E53935"          # Material Red 600
CLR_HIGH_BG = "#3B1212"       # deep-red tint for cards
CLR_HIGH_BORDER = "#B71C1C"

CLR_MEDIUM = "#FB8C00"        # Material Orange 600
CLR_MEDIUM_BG = "#2E1B06"
CLR_MEDIUM_BORDER = "#E65100"

CLR_LOW = "#78909C"           # Blue Grey 400 — "grey" as spec says
CLR_LOW_BG = "#1A2227"
CLR_LOW_BORDER = "#455A64"

# Verdict chips
CLR_KNOWN_ATTACK = "#EF5350"          # red, consistent with HIGH
CLR_KNOWN_ATTACK_BORDER = "#B71C1C"
CLR_NOVEL_ANOMALY = "#AB47BC"         # purple — unknown / novel
CLR_NOVEL_ANOMALY_BORDER = "#7B1FA2"
CLR_BENIGN = "#546E7A"                # muted

# Drift status
CLR_DRIFT_OK = "#43A047"             # green
CLR_DRIFT_OK_BG = "#0D2B0E"
CLR_DRIFT_WATCH = CLR_MEDIUM
CLR_DRIFT_WATCH_BG = CLR_MEDIUM_BG
CLR_DRIFT_ALERT = CLR_HIGH
CLR_DRIFT_ALERT_BG = CLR_HIGH_BG

# Confidence band
CLR_CONF_HIGH = "#26C6DA"            # cyan — high confidence
CLR_CONF_MEDIUM = CLR_MEDIUM
CLR_CONF_LOW = CLR_LOW

# Status pills
_STATUS_COLOURS: dict[str, tuple[str, str]] = {
    # (text-colour, background)
    "new":           ("#FFFFFF", "#1565C0"),   # blue — needs attention
    "acknowledged":  ("#FFFFFF", "#00838F"),   # teal
    "escalated":     ("#FFFFFF", "#B71C1C"),   # deep red
    "dismissed_fp":  ("#9E9E9E", "#263238"),   # muted grey — false positive closed
    "resolved":      ("#A5D6A7", "#1B5E20"),   # green — closed safely
}

# Dark background palette
BG_PAGE = "#0E1117"           # matches Streamlit's default dark page background
BG_CARD = "#161B22"           # slightly lighter — incident rows / cards
BG_CARD_HOVER = "#1C2431"
BG_SIDEBAR = "#0D1117"
BORDER_SUBTLE = "#30363D"     # GitHub-dark-inspired subtle divider

# Typography
FONT_MONO = "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace"
FONT_SANS = "'Inter', 'Segoe UI', sans-serif"

TXT_PRIMARY = "#E6EDF3"
TXT_SECONDARY = "#8B949E"
TXT_MUTED = "#6E7681"


# ---------------------------------------------------------------------------
# Global CSS injected once per page
# ---------------------------------------------------------------------------

_CSS = f"""
<style>
/* ── Base ─────────────────────────────────────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"] {{
    background-color: {BG_PAGE};
    color: {TXT_PRIMARY};
    font-family: {FONT_SANS};
}}

/* Remove Streamlit's default white card shadow on metric widgets */
[data-testid="metric-container"] {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 8px;
    padding: 12px 16px;
}}

/* Sidebar */
[data-testid="stSidebar"] {{
    background-color: {BG_SIDEBAR};
    border-right: 1px solid {BORDER_SUBTLE};
}}

/* ── Incident-row card ────────────────────────────────────────────────────── */
.ns-card {{
    background: {BG_CARD};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 6px;
    transition: background 0.15s;
    cursor: pointer;
}}
.ns-card:hover {{
    background: {BG_CARD_HOVER};
    border-color: #58A6FF;
}}
.ns-card-high  {{ border-left: 4px solid {CLR_HIGH};   }}
.ns-card-medium {{ border-left: 4px solid {CLR_MEDIUM}; }}
.ns-card-low   {{ border-left: 4px solid {CLR_LOW};    }}

/* New-row highlight (applied via JS fragment refresh in M4-03) */
.ns-card-new-flash {{
    animation: ns-flash 1.2s ease-out;
}}
@keyframes ns-flash {{
    0%   {{ background: #0D2744; }}
    100% {{ background: {BG_CARD}; }}
}}

/* ── Risk badge ───────────────────────────────────────────────────────────── */
.ns-risk-badge {{
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid;
    font-family: {FONT_MONO};
}}
.ns-risk-high   {{ color:{CLR_HIGH};   background:{CLR_HIGH_BG};   border-color:{CLR_HIGH_BORDER};   }}
.ns-risk-medium {{ color:{CLR_MEDIUM}; background:{CLR_MEDIUM_BG}; border-color:{CLR_MEDIUM_BORDER}; }}
.ns-risk-low    {{ color:{CLR_LOW};    background:{CLR_LOW_BG};    border-color:{CLR_LOW_BORDER};    }}

/* ── Verdict chip ─────────────────────────────────────────────────────────── */
.ns-chip {{
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 2px 10px;
    border-radius: 12px;
    border: 1px solid;
}}
.ns-chip-known   {{
    color:{CLR_KNOWN_ATTACK}; border-color:{CLR_KNOWN_ATTACK_BORDER};
    background:rgba(239,83,80,0.10);
}}
.ns-chip-novel   {{
    color:{CLR_NOVEL_ANOMALY}; border-color:{CLR_NOVEL_ANOMALY_BORDER};
    background:rgba(171,71,188,0.10);
}}
.ns-chip-benign  {{ color:{CLR_BENIGN}; border-color:{CLR_BENIGN}; background:transparent; }}

/* ── Status pill ──────────────────────────────────────────────────────────── */
.ns-pill {{
    display: inline-block;
    font-size: 0.70rem;
    font-weight: 600;
    padding: 2px 9px;
    border-radius: 10px;
    letter-spacing: 0.04em;
    text-transform: capitalize;
}}
.ns-pill-new          {{ color:#FFFFFF;  background:#1565C0; }}
.ns-pill-acknowledged {{ color:#FFFFFF;  background:#00838F; }}
.ns-pill-escalated    {{ color:#FFFFFF;  background:#B71C1C; }}
.ns-pill-dismissed_fp {{ color:#9E9E9E;  background:#263238; }}
.ns-pill-resolved     {{ color:#A5D6A7;  background:#1B5E20; }}

/* ── Family tag ───────────────────────────────────────────────────────────── */
.ns-family-tag {{
    display: inline-block;
    font-family: {FONT_MONO};
    font-size: 0.72rem;
    color: {TXT_SECONDARY};
    background: #21262D;
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 4px;
    padding: 1px 7px;
}}

/* ── Risk score number ────────────────────────────────────────────────────── */
.ns-score {{
    font-family: {FONT_MONO};
    font-size: 1.6rem;
    font-weight: 700;
    line-height: 1;
}}
.ns-score-high   {{ color: {CLR_HIGH};   }}
.ns-score-medium {{ color: {CLR_MEDIUM}; }}
.ns-score-low    {{ color: {CLR_LOW};    }}

/* ── Drift status banner ──────────────────────────────────────────────────── */
.ns-drift-banner {{
    padding: 10px 16px;
    border-radius: 8px;
    font-weight: 600;
    margin-bottom: 12px;
    border: 1px solid;
}}
.ns-drift-ok    {{ color:{CLR_DRIFT_OK};    background:{CLR_DRIFT_OK_BG};    border-color:{CLR_DRIFT_OK};    }}
.ns-drift-watch {{ color:{CLR_DRIFT_WATCH}; background:{CLR_DRIFT_WATCH_BG}; border-color:{CLR_DRIFT_WATCH}; }}
.ns-drift-alert {{ color:{CLR_DRIFT_ALERT}; background:{CLR_DRIFT_ALERT_BG}; border-color:{CLR_DRIFT_ALERT}; }}

/* ── Confidence badge ─────────────────────────────────────────────────────── */
.ns-conf-badge {{
    display: inline-block;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 1px 7px;
    border-radius: 4px;
}}
.ns-conf-high   {{ color:{CLR_CONF_HIGH};   background:rgba(38,198,218,0.12); }}
.ns-conf-medium {{ color:{CLR_CONF_MEDIUM}; background:rgba(251,140,0,0.12);  }}
.ns-conf-low    {{ color:{CLR_CONF_LOW};    background:rgba(120,144,156,0.12);}}

/* ── MITRE badge ──────────────────────────────────────────────────────────── */
.ns-mitre-badge {{
    display: inline-block;
    font-family: {FONT_MONO};
    font-size: 0.72rem;
    font-weight: 700;
    color: #58A6FF;
    background: rgba(88,166,255,0.10);
    border: 1px solid rgba(88,166,255,0.30);
    border-radius: 4px;
    padding: 2px 8px;
    text-decoration: none;
}}
.ns-mitre-badge:hover {{ background: rgba(88,166,255,0.20); }}

/* ── Utility ──────────────────────────────────────────────────────────────── */
.ns-muted     {{ color: {TXT_MUTED}; font-size: 0.82rem; }}
.ns-secondary {{ color: {TXT_SECONDARY}; }}
.ns-mono      {{ font-family: {FONT_MONO}; }}
.ns-divider   {{ border-top: 1px solid {BORDER_SUBTLE}; margin: 12px 0; }}

/* Streamlit dataframe / table dark override */
[data-testid="stDataFrame"] {{ border: 1px solid {BORDER_SUBTLE}; border-radius: 6px; }}
</style>
"""


def inject_css() -> None:
    """Inject the global dark-SOC stylesheet.

    Call once at the top of every page file, after ``st.set_page_config``.
    Subsequent calls on the same page are no-ops (Streamlit deduplicates
    identical ``st.markdown`` HTML blocks).
    """
    st.markdown(_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Risk level helpers
# ---------------------------------------------------------------------------

_LEVEL_CSS: dict[str, str] = {
    "HIGH":   "ns-risk-high",
    "MEDIUM": "ns-risk-medium",
    "LOW":    "ns-risk-low",
}

_LEVEL_SCORE_CSS: dict[str, str] = {
    "HIGH":   "ns-score-high",
    "MEDIUM": "ns-score-medium",
    "LOW":    "ns-score-low",
}

_LEVEL_CARD_CSS: dict[str, str] = {
    "HIGH":   "ns-card-high",
    "MEDIUM": "ns-card-medium",
    "LOW":    "ns-card-low",
}


def risk_badge(level: str) -> str:
    """Return an HTML risk-level badge: HIGH (red), MEDIUM (amber), LOW (grey).

    Args:
        level: One of ``"HIGH"``, ``"MEDIUM"``, ``"LOW"`` (case-insensitive).
    """
    css = _LEVEL_CSS.get(level.upper(), "ns-risk-low")
    return f'<span class="ns-risk-badge {css}">{level.upper()}</span>'


def risk_score_html(score: int, level: str) -> str:
    """Return the numeric risk score styled in the level's colour."""
    css = _LEVEL_SCORE_CSS.get(level.upper(), "ns-score-low")
    return f'<span class="ns-score {css}">{score}</span>'


def card_css_class(level: str) -> str:
    """Return the CSS modifier class for an incident-row card border."""
    return _LEVEL_CARD_CSS.get(level.upper(), "ns-card-low")


# ---------------------------------------------------------------------------
# Verdict chip helpers
# ---------------------------------------------------------------------------

_VERDICT_META: dict[str, tuple[str, str]] = {
    # (display label, CSS modifier)
    "known_attack":  ("Known attack",   "ns-chip-known"),
    "novel_anomaly": ("Novel anomaly",  "ns-chip-novel"),
    "benign":        ("Benign",         "ns-chip-benign"),
}


def verdict_chip(verdict: str) -> str:
    """Return an HTML chip for the verdict value from ``schemas.Verdict``.

    Args:
        verdict: ``"known_attack"``, ``"novel_anomaly"``, or ``"benign"``.
    """
    label, css = _VERDICT_META.get(verdict.lower(), (verdict, "ns-chip-benign"))
    return f'<span class="ns-chip {css}">{label}</span>'


# ---------------------------------------------------------------------------
# Status pill helpers
# ---------------------------------------------------------------------------

_STATUS_DISPLAY: dict[str, str] = {
    "new":           "New",
    "acknowledged":  "Acknowledged",
    "escalated":     "Escalated",
    "dismissed_fp":  "Dismissed FP",
    "resolved":      "Resolved",
}


def status_pill(status: str) -> str:
    """Return an HTML status pill for an ``IncidentStatus`` value.

    Args:
        status: ``"new"``, ``"acknowledged"``, ``"escalated"``,
                ``"dismissed_fp"``, or ``"resolved"``.
    """
    key = status.lower()
    label = _STATUS_DISPLAY.get(key, status.replace("_", " ").title())
    css = f"ns-pill-{key}"
    return f'<span class="ns-pill {css}">{label}</span>'


# ---------------------------------------------------------------------------
# Family tag helper
# ---------------------------------------------------------------------------

def family_tag(family: str) -> str:
    """Return a muted monospace tag for an ``AttackFamily`` display value."""
    return f'<span class="ns-family-tag">{family}</span>'


# ---------------------------------------------------------------------------
# Drift status badge
# ---------------------------------------------------------------------------

_DRIFT_META: dict[str, tuple[str, str]] = {
    "ok":    ("✓ OK — PSI within normal range",     "ns-drift-ok"),
    "watch": ("⚠ WATCH — PSI elevated (0.10–0.25)", "ns-drift-watch"),
    "alert": ("✕ ALERT — PSI high (≥ 0.25). Consider recalibrating.", "ns-drift-alert"),
}


def drift_status_banner(status: str) -> str:
    """Return a full-width HTML drift-status banner.

    Args:
        status: ``"ok"``, ``"watch"``, or ``"alert"`` (from ``DriftStatus``).
    """
    label, css = _DRIFT_META.get(status.lower(), (status.upper(), "ns-drift-watch"))
    return f'<div class="ns-drift-banner {css}">{label}</div>'


# ---------------------------------------------------------------------------
# Confidence badge
# ---------------------------------------------------------------------------

_CONF_META: dict[str, tuple[str, str]] = {
    "high":   ("High confidence",   "ns-conf-high"),
    "medium": ("Med. confidence",   "ns-conf-medium"),
    "low":    ("Low confidence",    "ns-conf-low"),
}


def confidence_badge(band: str) -> str:
    """Return an HTML confidence-band badge.

    Args:
        band: ``"high"``, ``"medium"``, or ``"low"`` (from ``ConfidenceBand``).
    """
    label, css = _CONF_META.get(band.lower(), (band, "ns-conf-low"))
    return f'<span class="ns-conf-badge {css}">{label}</span>'


# ---------------------------------------------------------------------------
# MITRE badge / link
# ---------------------------------------------------------------------------

_MITRE_BASE = "https://attack.mitre.org/techniques"


def mitre_badge(technique_id: str | None, technique_name: str | None) -> str:
    """Return an HTML MITRE badge that links to attack.mitre.org.

    Returns an empty string if both arguments are ``None`` (i.e. novel anomaly
    or benign — no MITRE mapping exists).
    """
    if not technique_id:
        return ""
    name_part = f" — {technique_name}" if technique_name else ""
    url = f"{_MITRE_BASE}/{technique_id.replace('.', '/')}/"
    return (
        f'<a class="ns-mitre-badge" href="{url}" target="_blank" rel="noopener">'
        f"{technique_id}{name_part}"
        f"</a>"
    )


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def muted(text: str) -> str:
    """Wrap ``text`` in a muted-colour span."""
    return f'<span class="ns-muted">{text}</span>'


def mono(text: str) -> str:
    """Wrap ``text`` in a monospace span."""
    return f'<span class="ns-mono">{text}</span>'


def divider() -> str:
    """Return a subtle horizontal rule HTML string."""
    return '<div class="ns-divider"></div>'


def bundle_badge(feature_schema: str, model_version: str) -> str:
    """Return a bundle/schema pill for the sidebar.

    Shows '2018' (blue) for CIC schema or 'LUFlow' (green) for the LUFlow bundle.
    """
    if feature_schema == "cic":
        colour, label = "#1565C0", "2018"
    else:
        colour, label = "#2E7D32", "LUFlow"
    return (
        f'<span style="display:inline-block;background:{colour};color:#fff;'
        f'font-size:0.70rem;font-weight:700;padding:2px 8px;border-radius:4px;'
        f'letter-spacing:0.05em;">{label}</span>&nbsp;'
        f'<span class="ns-muted ns-mono">{model_version}</span>'
    )


# ---------------------------------------------------------------------------
# Analyst sign-in & session management (M4-05)
# ---------------------------------------------------------------------------

ANALYST_ROLES: list[str] = [
    "SOC Analyst",
    "Tier-2 Analyst",
    "Incident Responder",
    "Threat Hunter",
    "Manager",
]


def init_analyst_session() -> None:
    """Ensure analyst session state keys exist."""
    if "analyst_name" not in st.session_state or not st.session_state["analyst_name"]:
        st.session_state["analyst_name"] = "Asha Patel"
    if "analyst_role" not in st.session_state or not st.session_state["analyst_role"]:
        st.session_state["analyst_role"] = "SOC Analyst"


def get_analyst() -> tuple[str, str, str]:
    """Return (name, role, x_analyst_header).

    x_analyst_header is formatted as 'Name (Role)' sent in X-Analyst header.
    """
    init_analyst_session()
    name = str(st.session_state.get("analyst_name", "")).strip() or "Asha Patel"
    role = str(st.session_state.get("analyst_role", "")).strip() or "SOC Analyst"
    header = f"{name} ({role})"
    return name, role, header


def analyst_badge(name: str, role: str) -> str:
    """Return an HTML badge for the active signed-in analyst."""
    return (
        f'<span style="display:inline-flex;align-items:center;gap:6px;'
        f'background:{BG_CARD};border:1px solid {BORDER_SUBTLE};'
        f'padding:3px 10px;border-radius:14px;font-size:0.75rem;">'
        f'<span style="color:{CLR_CONF_HIGH};font-weight:700;">👤 {name}</span>'
        f'<span style="color:{TXT_MUTED};">·</span>'
        f'<span style="color:{TXT_SECONDARY};">{role}</span>'
        f'</span>'
    )


def render_analyst_sidebar() -> tuple[str, str, str]:
    """Render the analyst sign-in and profile card in the Streamlit sidebar.

    Returns (name, role, x_analyst_header).
    """
    init_analyst_session()
    name, role, header = get_analyst()

    with st.sidebar:
        st.markdown(
            f"<div style='background:{BG_CARD};border:1px solid {BORDER_SUBTLE};"
            f"border-radius:6px;padding:8px 12px;margin-bottom:8px;'>"
            f"<div style='font-size:0.70rem;color:{TXT_MUTED};text-transform:uppercase;"
            f"letter-spacing:0.05em;'>Active Analyst</div>"
            f"<div style='font-weight:700;color:{TXT_PRIMARY};font-size:0.92rem;line-height:1.3;'>"
            f"{name}</div>"
            f"<div style='font-size:0.75rem;color:{CLR_CONF_HIGH};'>{role}</div>"
            f"<div style='font-size:0.68rem;color:{TXT_MUTED};margin-top:4px;"
            f"font-family:{FONT_MONO};'>X-Analyst: {header}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )
        with st.expander("👤 Analyst Sign-in / Role", expanded=False):
            new_name = st.text_input(
                "Name",
                value=name,
                placeholder="e.g. Asha Patel",
                key="_analyst_name_input_shared",
            )
            role_idx = ANALYST_ROLES.index(role) if role in ANALYST_ROLES else 0
            new_role = st.selectbox(
                "Role",
                ANALYST_ROLES,
                index=role_idx,
                key="_analyst_role_select_shared",
            )
            if new_name != name or new_role != role:
                st.session_state["analyst_name"] = new_name
                st.session_state["analyst_role"] = new_role
                st.rerun()

    return st.session_state["analyst_name"], st.session_state["analyst_role"], get_analyst()[2]

