"""One render function per dashboard section. Each receives the already-filtered dataframe."""
import pandas as pd
import streamlit as st

from . import analysis as A
from . import visualization as V
from .data_cleaning import MISSING
from .data_loader import DATA_FILE, EXPECTED_COLUMN_COUNT, SHEET_NAME
from .insights import generate_insights
from .ui import exclusion_caption, insight_cards, kpi_cards, note, section_header, show_figure

MULTI_VALUE_NOTE = ("An incident is counted once under each distinct value it contains, "
                    "so shares can add up to more than 100%.")


# ----------------------------------------------------------------------------- shared helpers
def count_chart(df, col, title, top_n=10, exclude=A.NOT_RANKED, color=V.CYAN, what=None):
    """Ranked horizontal bar chart of a (possibly multi-valued) categorical field."""
    counts = A.count_values(df, col, exclude=exclude, top_n=top_n)
    caption = exclusion_caption(len(df), A.coverage(df, col, exclude), what or col.replace("_", " "))
    show_figure(V.hbar, counts, "value", "incidents", title, pct_col="share_pct", color=color, caption=caption)


def donut_chart(df, col, title, exclude=A.NOT_RANKED, what=None):
    counts = A.count_values(df, col, exclude=exclude)
    caption = exclusion_caption(len(df), A.coverage(df, col, exclude), what or col.replace("_", " "))
    if len(counts) > 6:                       # too many slices -> fall back to bars
        show_figure(V.hbar, counts.head(8), "value", "incidents", title, pct_col="share_pct", caption=caption)
    else:
        show_figure(V.donut, counts, "value", "incidents", title, caption=caption)


def heat_chart(df, col_a, col_b, title, xlabel, ylabel, top_a=10, top_b=8, exclude_a=A.NOT_RANKED,
               exclude_b=A.NOT_RANKED):
    matrix = A.cross_counts(df, col_a, col_b, top_a, top_b, exclude_a, exclude_b)
    show_figure(V.heatmap, matrix, title, xlabel, ylabel,
                caption="Cells show incidents recorded with both values (unavailable values excluded).")


def top_n_slider(key, default=10, maximum=25):
    return st.slider("Show top N", 5, maximum, default, key=key)


# ----------------------------------------------------------------------------- 1. overview
def build_kpis(df) -> list:
    """Only KPIs that can be calculated from the current selection are returned."""
    items = [("Total incidents", f"{len(df):,}", "recorded in this dataset")]
    countries = A.count_values(df, "receiver_country")
    if not countries.empty:
        items.append(("Receiver countries", f"{len(countries):,}", "distinct, unavailable excluded"))
    types = A.count_values(df, "incident_type")
    if not types.empty:
        items.append(("Incident types", f"{len(types):,}", "distinct recorded types"))
    disruption = int(df["has_disruption"].sum())
    items.append(("With disruption", f"{disruption:,}", f"{disruption / len(df) * 100:.1f}% of incidents"))
    theft = A.data_theft_summary(df)
    if theft["known"] > 0:
        items.append(("With data theft", f"{theft['recorded']:,}",
                      f"{theft['recorded'] / theft['known'] * 100:.1f}% of {theft['known']:,} with data"))
    intensity = pd.to_numeric(df["weighted_intensity"], errors="coerce").dropna()
    if not intensity.empty:
        items.append(("Avg weighted intensity", f"{intensity.mean():.2f}", f"across {len(intensity):,} incidents"))
    return items


def render_overview(df):
    section_header("Executive Overview",
                   "Snapshot of the recorded incidents that match the current filters.")
    kpi_cards(build_kpis(df))
    st.write("")
    section_header("Intelligence Insights", "Generated live from the filtered data - nothing is hard-coded.")
    insight_cards(generate_insights(df))

    left, right = st.columns(2)
    with left:
        yearly = A.incidents_per_year(df)
        show_figure(V.vbar, yearly["Year"], yearly["incidents"], "Recorded incidents per year (start date)",
                    "Year", caption="Highest year highlighted. More records do not necessarily mean more "
                                    "real-world incidents. Incidents without a valid start date are not shown.")
        count_chart(df, "receiver_country", "Top receiver countries", 10, what="receiver country")
        donut_chart(df, "impact_indicator_label", "Impact indicator distribution", what="impact indicator")
    with right:
        count_chart(df, "incident_type", "Top incident types", 10, color=V.INDIGO, what="incident type")
        count_chart(df, "initiator_country", "Top recorded initiator countries", 10, exclude=A.NOT_RANKED_INITIATOR,
                    color=V.AMBER, what="attributed initiator country")
        counts = A.distribution_of_numeric(df, "weighted_intensity")
        show_figure(V.vbar, counts["value"], counts["incidents"], "Weighted intensity distribution",
                    "Weighted intensity score", highlight_max=False, color=V.GREEN)
    note(MULTI_VALUE_NOTE)


# ----------------------------------------------------------------------------- 2. threat landscape
def render_threat_landscape(df):
    section_header("Threat Landscape", "Which incident types, countries, regions and sectors appear most often.")
    top_n = top_n_slider("top_threat")
    left, right = st.columns(2)
    with left:
        count_chart(df, "receiver_country", "Top receiver countries", top_n, what="receiver country")
        count_chart(df, "receiver_category", "Receiver categories", top_n, color=V.INDIGO, what="receiver category")
    with right:
        count_chart(df, "incident_type", "Incident type distribution", top_n, color=V.AMBER, what="incident type")
        count_chart(df, "receiver_regions", "Receiver regions / alliances", top_n, color=V.GREEN, what="receiver region")
    heat_chart(df, "receiver_country", "incident_type", "Receiver country x incident type",
               "Incident type", "Receiver country", top_a=min(top_n, 15), top_b=7)
    count_chart(df, "receiver_subcategory", "Receiver subcategories", top_n, color=V.CYAN, what="receiver subcategory")
    note(MULTI_VALUE_NOTE)


# ----------------------------------------------------------------------------- 3. MITRE
def render_mitre(df):
    section_header("Attack & MITRE Intelligence",
                   "Recorded techniques and effects. MITRE fields are unavailable for many incidents.")
    ia_known = A.coverage(df, "mitre_initial_access")
    imp_known = A.coverage(df, "mitre_impact")
    note(f"MITRE initial access is recorded for {ia_known:,} of {len(df):,} incidents and MITRE impact for "
         f"{imp_known:,}. Incidents without a value are excluded from the rankings, not counted as a category.")
    top_n = top_n_slider("top_mitre", 8, 15)
    left, right = st.columns(2)
    with left:
        count_chart(df, "mitre_initial_access", "MITRE initial access", top_n, what="initial-access value")
        count_chart(df, "zero_days", "Zero-day exploitation recorded", 6, exclude=(), color=V.ROSE)
    with right:
        count_chart(df, "mitre_impact", "MITRE impact", top_n, color=V.INDIGO, what="impact value")
        count_chart(df, "user_interaction", "User interaction required", 6, exclude=(), color=V.GREEN)

    table = A.occurrence_table(df, {"Disruption": "disruption", "Data theft": "data_theft", "Hijacking": "hijacking"})
    show_figure(V.stacked_hbar, table, "Recorded effects: disruption, data theft, hijacking",
                colors=[V.CYAN, "#64748b", V.AMBER],
                caption="'Not available' means the dataset holds no information - it is not counted as 'none'.")
    heat_chart(df, "mitre_initial_access", "mitre_impact", "MITRE initial access x MITRE impact",
               "MITRE impact", "MITRE initial access", 8, 8)
    heat_chart(df, "incident_type", "mitre_impact", "Incident type x MITRE impact",
               "MITRE impact", "Incident type", 8, 8)


# ----------------------------------------------------------------------------- 4. targets & initiators
def render_targets_initiators(df):
    section_header("Target & Initiator Intelligence",
                   "Who is recorded as receiving incidents and who is recorded as initiating them.")
    top_n = top_n_slider("top_ti")
    targets, initiators = st.tabs(["Targets (receivers)", "Initiators"])
    with targets:
        left, right = st.columns(2)
        with left:
            count_chart(df, "receiver_country", "Most targeted countries (recorded)", top_n, what="receiver country")
            count_chart(df, "receiver_subcategory", "Receiver subcategories", top_n, color=V.AMBER, what="subcategory")
        with right:
            count_chart(df, "receiver_category", "Receiver categories", top_n, color=V.INDIGO, what="category")
            count_chart(df, "receiver_name", "Most frequently named receivers", min(top_n, 15), color=V.GREEN,
                        what="receiver name")
        heat_chart(df, "receiver_category", "incident_type", "Incident types by receiver category",
                   "Incident type", "Receiver category", 8, 7)
    with initiators:
        note("'Recorded initiator' reflects what the dataset lists. Incidents marked 'Not attributed' or "
             "'Unknown' are shown separately and are not treated as findings about any actor.")
        left, right = st.columns(2)
        with left:
            count_chart(df, "initiator_country", "Recorded initiator countries", top_n,
                        exclude=A.NOT_RANKED_INITIATOR, what="attributed initiator country")
            donut_chart(df, "initiator_category", "Initiator category (state vs non-state)", what="initiator category")
            count_chart(df, "initiator_name", "Named initiators", min(top_n, 15), exclude=A.NOT_RANKED_INITIATOR,
                        color=V.GREEN, what="initiator name")
        with right:
            show_figure(V.donut, A.attribution_status(df), "value", "incidents", "Initiator country: recorded vs not attributed")
            count_chart(df, "initiator_subcategory", "Initiator subcategory", top_n, color=V.AMBER, what="subcategory")
            count_chart(df, "state_responsibility_actor", "State responsibility (as coded)", 6, color=V.ROSE,
                        what="state-responsibility coding")
        heat_chart(df, "initiator_country", "receiver_country", "Recorded initiator country x receiver country",
                   "Receiver country", "Initiator country", 10, 10, exclude_a=A.NOT_RANKED_INITIATOR)


# ----------------------------------------------------------------------------- 5. impact
def render_impact(df):
    section_header("Impact Analysis", "Intensity, functional and intelligence impact, plus economic and casualty data.")
    left, right = st.columns(2)
    with left:
        counts = A.distribution_of_numeric(df, "weighted_intensity")
        show_figure(V.vbar, counts["value"], counts["incidents"], "Weighted intensity distribution",
                    "Weighted intensity score", highlight_max=False, color=V.GREEN)
        count_chart(df, "functional_impact", "Functional impact", 8, color=V.INDIGO, what="functional impact")
        count_chart(df, "affected_entities", "Affected entities (range)", 8, color=V.AMBER, what="affected-entities range")
    with right:
        donut_chart(df, "impact_indicator_label", "Impact indicator label", what="impact indicator")
        count_chart(df, "intelligence_impact", "Intelligence impact", 8, color=V.ROSE, what="intelligence impact")
        count_chart(df, "affected_third_countries", "Affected third countries (range)", 8, what="third-country range")

    by_type = A.mean_by_category(df, "incident_type", min_count=5)
    show_figure(V.hbar, by_type, "value", "mean", "Average weighted intensity by incident type",
                xlabel="Average weighted intensity", color=V.AMBER,
                caption="Incident types with fewer than 5 incidents are hidden.")
    by_category = A.mean_by_category(df, "receiver_category", min_count=10).head(10)
    show_figure(V.hbar, by_category, "value", "mean", "Average weighted intensity by receiver category",
                xlabel="Average weighted intensity", color=V.CYAN,
                caption="Receiver categories with fewer than 10 incidents are hidden.")

    section_header("Economic impact", "Handled with care: missing is never treated as zero.")
    note("The workbook mixes euro and dollar amounts, and most incidents have no economic information. "
         "Amounts are therefore never added together; only category counts and per-currency summaries are shown.")
    economic = A.economic_category_counts(df)
    c1, c2 = st.columns(2)
    with c1:
        show_figure(V.hbar, economic, "value", "incidents", "Economic impact category (as coded)",
                    color=V.INDIGO, caption="'0' is a coded value; 'Not available' and blank cells are different "
                                            "kinds of missing information.")
    with c2:
        with st.container(border=True):
            st.markdown("**Recorded amounts (value > 0) by currency**")
            by_currency = A.economic_value_by_currency(df)
            if by_currency.empty:
                st.info("No positive economic values with a stated currency in this selection.")
            else:
                st.dataframe(by_currency, hide_index=True)
                st.caption("Median and maximum are shown per currency (euro and dollar are separate). The workbook "
                           "does not state what a value of 0 means, so zeros are not interpreted.")

    casualties_known = int((df["casualties"] != MISSING).sum())
    if casualties_known == 0:
        note("Casualties: the 'casualties' field is 'Not available' for every incident in this selection, "
             "so no casualty analysis can be shown.")
    else:
        st.dataframe(df.loc[df["casualties"] != MISSING, ["incident_id", "name", "casualties"]], hide_index=True)


# ----------------------------------------------------------------------------- 6. attribution
def render_attribution(df):
    section_header("Attribution & Geopolitical Response",
                   "How recorded initiators were attributed and the conflict context. Neutral reading only.")
    note("Attribution here means what the dataset records; it is not proof and the dashboard does not assert guilt.")
    top_n = top_n_slider("top_attr", 8, 15)
    left, right = st.columns(2)
    with left:
        show_figure(V.donut, A.attribution_status(df), "value", "incidents", "Attribution status (initiator country)")
        count_chart(df, "attribution_basis", "Attribution basis", top_n, color=V.INDIGO, what="attribution basis")
        count_chart(df, "cyber_conflict_issue", "Cyber conflict issue", top_n, exclude=(MISSING, "Unknown"),
                    color=V.AMBER, what="known conflict issue")
    with right:
        counts = df["number_attributions"].value_counts().sort_index().rename_axis("value").reset_index(name="incidents")
        show_figure(V.vbar, counts["value"], counts["incidents"], "Number of attributions per incident",
                    "Number of attributions", highlight_max=False, color=V.GREEN)
        count_chart(df, "state_responsibility_actor", "State responsibility (as coded)", 6, color=V.ROSE,
                    what="state-responsibility coding")
        count_chart(df, "attributing_country", "Attributing country", top_n, what="attributing country")
    count_chart(df, "offline_conflict_name", "Linked offline conflicts", top_n, color=V.CYAN, what="offline conflict")
    heat_chart(df, "initiator_country", "cyber_conflict_issue", "Recorded initiator country x cyber conflict issue",
               "Cyber conflict issue", "Initiator country", 8, 7, exclude_a=A.NOT_RANKED_INITIATOR,
               exclude_b=(MISSING, "Unknown"))


# ----------------------------------------------------------------------------- 7. responses
def render_responses(df):
    section_header("Response Analysis", "Recorded political and legal responses. Counts show co-occurrence, not causation.")
    presence = A.response_presence(df)
    kpi_cards([
        ("Incidents with political response", f"{presence['political']:,}",
         f"{presence['political'] / presence['total'] * 100:.1f}% of incidents"),
        ("Incidents with legal response", f"{presence['legal']:,}",
         f"{presence['legal'] / presence['total'] * 100:.1f}% of incidents"),
    ])
    st.write("")
    top_n = top_n_slider("top_resp", 8, 15)
    left, right = st.columns(2)
    with left:
        count_chart(df, "political_response_type", "Political response types", top_n, color=V.INDIGO, what="political response")
        count_chart(df, "response_indicator", "Response indicator", 6, color=V.AMBER, what="response indicator")
    with right:
        count_chart(df, "legal_response_type", "Legal response types", top_n, color=V.GREEN, what="legal response")
        recorded = int((df["evidence_for_sanctions_indicator"] != MISSING).sum())
        note(f"The evidence-for-sanctions indicator is recorded for only {recorded:,} of {len(df):,} "
             "incidents in this selection, so no chart is shown.")
    yearly = A.responses_by_year(df)
    if not yearly.empty:
        show_figure(V.line_chart, list(yearly.index), {c: yearly[c] for c in yearly.columns},
                    "Incidents with a recorded response, by year of incident start", "Year",
                    caption="Based on number_political_responses / number_legal_responses > 0. These counts can "
                            "differ slightly from the type breakdowns above because the type fields are coded separately.")


# ----------------------------------------------------------------------------- 8. timeline
def render_timeline(df):
    section_header("Timeline Analysis", "Recorded incidents by start date. This is not a measure of real-world crime rates.")
    yearly = A.incidents_per_year(df)
    left, right = st.columns(2)
    with left:
        show_figure(V.vbar, yearly["Year"], yearly["incidents"], "Recorded incidents per year", "Year")
    with right:
        intensity = A.mean_intensity_per_year(df)
        show_figure(V.line_chart, list(intensity["Year"]), {"Average weighted intensity": intensity["mean_weighted_intensity"]},
                    "Average weighted intensity per year", "Year", ylabel="Average weighted intensity")
    monthly = A.incidents_per_month(df)
    show_figure(V.line_chart, list(monthly["YearMonth"]), {"Incidents": monthly["incidents"]},
                "Recorded incidents per month", "Year-Month",
                caption="Only incidents with a valid start date appear on timeline charts.")

    options = {"Incident type": "incident_type", "Receiver category": "receiver_category",
               "Initiator category": "initiator_category", "Receiver country": "receiver_country"}
    choice = st.selectbox("Show major categories over time for:", list(options), key="timeline_dim")
    top_k = st.slider("Number of categories", 3, 8, 5, key="timeline_k")
    table = A.category_by_year(df, options[choice], top_k)
    if table.empty:
        st.info("No dated incidents with usable values for this selection.")
    else:
        show_figure(V.line_chart, list(table.index), {c: table[c] for c in table.columns},
                    f"{choice}: top {top_k} over time", "Year")


# ----------------------------------------------------------------------------- 9. explorer
EXPLORER_DEFAULT_COLUMNS = [
    "incident_id", "name", "start_date", "incident_type", "receiver_country", "receiver_category",
    "initiator_country", "initiator_category", "mitre_initial_access", "mitre_impact",
    "weighted_intensity", "impact_indicator_label", "economic_impact", "response_indicator",
]
DETAIL_FIELDS = ["start_date", "end_date", "incident_type", "receiver_name", "receiver_country", "receiver_category",
                 "initiator_name", "initiator_country", "initiator_category", "mitre_initial_access", "mitre_impact",
                 "weighted_intensity", "impact_indicator_label", "functional_impact", "intelligence_impact",
                 "economic_impact", "economic_impact_value", "economic_impact_currency", "response_indicator",
                 "state_responsibility_actor", "cyber_conflict_issue"]


def render_explorer(df):
    section_header("Data Explorer", "Inspect the individual incident records behind every chart.")
    all_columns = [c for c in df.columns if not c.endswith("__list") and not c.endswith("_parsed")
                   and c not in ("Year", "Month", "YearMonth")]
    chosen = st.multiselect("Columns to show", all_columns, default=EXPLORER_DEFAULT_COLUMNS, key="explorer_cols")
    query = st.text_input("Search incident name or description", key="explorer_search").strip()
    view = df
    if query:
        text = (df["name"].astype(str) + " " + df["description"].astype(str)).str.contains(query, case=False, regex=False)
        view = df[text]
    view = view.sort_values("start_date_parsed", ascending=False, na_position="last")
    st.caption(f"{len(view):,} incidents shown (newest first). Original values are displayed unchanged, "
               "including 'Not available'.")
    if not chosen:
        st.info("Select at least one column to display.")
    elif view.empty:
        st.info("No incidents match the search text.")
    else:
        st.dataframe(view[chosen], hide_index=True, height=420)
        st.download_button("Download this table as CSV", view[chosen].to_csv(index=False).encode("utf-8"),
                           file_name="filtered_incidents.csv", mime="text/csv")

    if not view.empty:
        st.markdown("#### Incident detail")
        labels = {row.incident_id: f"{row.incident_id} - {str(row.name)[:80]}" for row in view.head(1500).itertuples()}
        incident_id = st.selectbox("Choose an incident", list(labels), format_func=labels.get, key="explorer_incident")
        record = view[view["incident_id"] == incident_id].iloc[0]
        with st.container(border=True):
            st.markdown(f"**{record['name']}**")
            facts = pd.DataFrame({"Field": DETAIL_FIELDS, "Value": [str(record[f]) for f in DETAIL_FIELDS]})
            st.dataframe(facts, hide_index=True)
            st.write(record["description"])
            if str(record["source_url"]).startswith("http"):
                st.markdown(f"[Source link recorded in the dataset]({record['source_url']})")


# ----------------------------------------------------------------------------- 10. methodology
def render_methodology(full_df, raw_df):
    section_header("Methodology & Dataset", "Exactly what this dashboard analyses and its limits.")
    coverage = A.date_coverage(full_df)
    first = coverage["first"].strftime("%d %b %Y") if coverage["first"] is not None else "n/a"
    last = coverage["last"].strftime("%d %b %Y") if coverage["last"] is not None else "n/a"
    st.markdown(f"""
**This dashboard analyzes recorded incidents contained in the supplied dataset. It does not show verified global
crime statistics, and it makes no claim about causation.**

- **File:** `{DATA_FILE.name}` - **Sheet:** `{SHEET_NAME}`
- **Records:** {len(raw_df):,} - **Fields:** {raw_df.shape[1]} (expected {EXPECTED_COLUMN_COUNT})
- **Date coverage (valid `start_date`):** {first} to {last}. {coverage['valid']:,} incidents have a valid start date;
  {coverage['invalid']:,} do not (the field is 'Not available') and are left out of timeline charts only.
- **Dataset author/source:** not stated inside the workbook, so none is claimed here.
""")
    st.markdown("""
**Cleaning approach**
- The original workbook data is never altered; a cleaned copy is used for analysis.
- Blank cells and the text "Not available" are both shown as **Not available** and are *not* turned into a real category.
  They are excluded from rankings, and each chart says how many incidents were left out.
- Dates stored as text (`dd.mm.yyyy` or `yyyy-mm-dd`) are parsed; unparseable dates stay empty rather than guessed.
- Multi-valued cells such as `United States;United States` are split on `;` (not inside brackets), de-duplicated per
  incident, and counted **once per distinct value**. Totals across categories can therefore exceed the incident count.
- 'Not attributed' and 'Unknown' initiators are reported as such and excluded from initiator-country rankings.

**Economic impact limitations**
- Most incidents have no economic information (blank or 'Not available'); these are never counted as zero.
- Amounts are recorded in euro or dollar; they are not converted or summed. Only category counts and per-currency
  median/maximum are shown. The workbook does not explain what a value of 0 means.
- The `casualties` field is 'Not available' for every record, so casualties are not analysed.

**Analytical limitations**
- More recorded incidents does not mean more real-world incidents: recording depends on disclosure and reporting.
- Counts are descriptive. Co-occurrence of incidents and responses is not evidence that one caused the other.
- "Highest number of recorded incidents in this dataset" is not the same as "most attacked in the world".
""")
    summary = A.missing_summary(raw_df)
    with st.expander("Missing / 'Not available' values per original column", expanded=False):
        st.dataframe(summary, hide_index=True, height=360)
    with st.expander("All columns in the workbook", expanded=False):
        st.write(", ".join(str(c) for c in raw_df.columns))
