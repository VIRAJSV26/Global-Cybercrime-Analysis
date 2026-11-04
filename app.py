"""GLOBAL CYBERCRIME ANALYSIS & INTELLIGENCE DASHBOARD - Streamlit entry point.

Run with:  streamlit run app.py
"""
from pathlib import Path

import streamlit as st

from src import analysis as A
from src import chatbot as CB
from src import pages
from src.data_cleaning import clean_dataset
from src.data_loader import DatasetError, load_validated_dataset

st.set_page_config(page_title="Global Cybercrime Analysis & Intelligence", page_icon="🛡️", layout="wide")

STYLE_FILE = Path(__file__).parent / "assets" / "style.css"

# (sidebar label, column) - chosen because they answer the main analytical questions
FILTERS = [
    ("Receiver country", "receiver_country"),
    ("Initiator country", "initiator_country"),
    ("Incident type", "incident_type"),
    ("Receiver category", "receiver_category"),
    ("Initiator category", "initiator_category"),
    ("MITRE initial access", "mitre_initial_access"),
    ("MITRE impact", "mitre_impact"),
    ("Impact indicator", "impact_indicator_label"),
    ("Functional impact", "functional_impact"),
    ("State responsibility", "state_responsibility_actor"),
    ("Response indicator", "response_indicator"),
]
YEAR_KEY, UNDATED_KEY = "flt_year", "flt_undated"

SECTIONS = [
    "Executive Overview",
    "Threat Landscape",
    "Attack & MITRE Intelligence",
    "Target & Initiator Intelligence",
    "Impact Analysis",
    "Attribution & Geopolitical Response",
    "Response Analysis",
    "Timeline Analysis",
    "Data Explorer",
    "AI Cyber Analyst",
    "Methodology / Dataset",
]


@st.cache_data(show_spinner="Loading the EuRepoC workbook...")
def load_data():
    """Read, validate and clean the workbook once; also prepare the filter options."""
    raw = load_validated_dataset()
    cleaned = clean_dataset(raw)
    options = {col: A.filter_options(cleaned, col) for _, col in FILTERS}
    return raw, cleaned, options


def inject_style():
    if STYLE_FILE.exists():
        st.markdown(f"<style>{STYLE_FILE.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def render_hero():
    st.markdown(
        """
        <div class="hero">
          <div class="hero-tag">CYBER INCIDENT INTELLIGENCE &nbsp;//&nbsp; RECORDED-INCIDENT ANALYSIS</div>
          <h1>GLOBAL CYBERCRIME<br><span>ANALYSIS &amp; INTELLIGENCE</span></h1>
          <p>An interactive dashboard that analyzes the recorded cyber incidents contained in the supplied
          EuRepoC dataset. Every number is calculated from that file and responds to your filters.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


inject_style()

try:
    raw_df, df, filter_options = load_data()
except DatasetError as error:
    render_hero()
    st.error(f"The dataset could not be loaded.\n\n{error}")
    st.stop()
except Exception as error:  # unexpected problem: show a short message, not a traceback
    render_hero()
    st.error(f"An unexpected error occurred while preparing the data ({type(error).__name__}).")
    st.stop()

years = df["Year"].dropna().astype(int)
year_min, year_max = (int(years.min()), int(years.max())) if not years.empty else (2000, 2024)


def reset_filters():
    for _, column in FILTERS:
        st.session_state["flt_" + column] = []
    st.session_state[YEAR_KEY] = (year_min, year_max)
    st.session_state[UNDATED_KEY] = True


# ---------------------------------------------------------------- sidebar: navigation + filters
with st.sidebar:
    st.markdown('<div class="brand"><b>🛡️ CYBER INTEL</b><div>RECORDED INCIDENT DASHBOARD</div></div>',
                unsafe_allow_html=True)
    section = st.radio("Navigate", SECTIONS, label_visibility="collapsed", key="nav")
    st.markdown("---")
    st.markdown("**Global filters**")

    st.session_state.setdefault(YEAR_KEY, (year_min, year_max))
    st.session_state.setdefault(UNDATED_KEY, True)
    for _, column in FILTERS:
        st.session_state.setdefault("flt_" + column, [])

    year_range = st.slider("Year (incident start date)", year_min, year_max, key=YEAR_KEY)
    include_undated = st.checkbox("Include incidents without a valid start date", key=UNDATED_KEY)
    selections = {}
    with st.expander("More filters", expanded=False):
        for label, column in FILTERS:
            selections[column] = st.multiselect(label, filter_options[column], key="flt_" + column)
    st.button("RESET FILTERS", on_click=reset_filters)

filtered = A.apply_filters(df, selections, year_range, include_undated)
active = sum(bool(v) for v in selections.values()) + int(year_range != (year_min, year_max)) + int(not include_undated)
st.sidebar.markdown(
    f'<div class="filter-status">Showing <b>{len(filtered):,}</b> of <b>{len(df):,}</b> incidents'
    f'<br>{active} active filter(s)</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------- main area
render_hero()

RENDERERS = {
    "Executive Overview": pages.render_overview,
    "Threat Landscape": pages.render_threat_landscape,
    "Attack & MITRE Intelligence": pages.render_mitre,
    "Target & Initiator Intelligence": pages.render_targets_initiators,
    "Impact Analysis": pages.render_impact,
    "Attribution & Geopolitical Response": pages.render_attribution,
    "Response Analysis": pages.render_responses,
    "Timeline Analysis": pages.render_timeline,
    "Data Explorer": pages.render_explorer,
    "AI Cyber Analyst": CB.render_chat_page,
}

if section == "Methodology / Dataset":
    pages.render_methodology(df, raw_df)
elif filtered.empty:
    st.warning("No incidents match the selected filters.")
    st.info("Widen the filters or press RESET FILTERS in the sidebar.")
else:
    try:
        RENDERERS[section](filtered)
    except Exception as error:
        st.error(f"This section could not be displayed ({type(error).__name__}). Try changing the filters.")

# ---------------------------------------------------------------- floating AI chatbot button
if st.button("🛡️ Ask AI Analyst", key="floating_chat_btn", help="Open EuRepoC AI Cyber Threat Assistant"):
    CB.render_chat_dialog(df)

