"""All calculations of the dashboard. Every number comes from the (filtered) dataset.

Counting rule for multi-valued fields: an incident is counted ONCE under each distinct
value it contains, so category totals can exceed the number of incidents.
"""
import numpy as np
import pandas as pd

from .data_cleaning import BLANK_ECONOMIC, LIST_SUFFIX, MISSING, NON_ATTRIBUTED, to_float_array

NOT_RANKED = (MISSING,)                       # excluded from rankings by default
NOT_RANKED_INITIATOR = (MISSING,) + NON_ATTRIBUTED


# ----------------------------------------------------------------------------- filtering
def count_values(df: pd.DataFrame, col: str, exclude=NOT_RANKED, top_n=None) -> pd.DataFrame:
    """Incidents per distinct value of `col` -> columns: value, incidents, share_pct."""
    columns = ["value", "incidents", "share_pct"]
    if df.empty:
        return pd.DataFrame(columns=columns)
    values = df[col + LIST_SUFFIX].explode()
    values = values[~values.isin(exclude)]
    counts = values.value_counts()
    result = counts.rename_axis("value").reset_index(name="incidents")
    result["share_pct"] = np.round(result["incidents"] / len(df) * 100, 1)
    if top_n:
        result = result.head(top_n)
    return result[columns].reset_index(drop=True)


def filter_options(df: pd.DataFrame, col: str) -> list:
    """All distinct values of a column, most frequent first (used by sidebar filters)."""
    return count_values(df, col, exclude=())["value"].tolist()


def apply_filters(df: pd.DataFrame, selections: dict, year_range=None, include_undated=True):
    """Keep incidents matching every active filter (multi-valued cells match if ANY value matches)."""
    mask = np.ones(len(df), dtype=bool)
    for col, chosen in selections.items():
        if chosen:
            wanted = set(chosen)
            mask &= df[col + LIST_SUFFIX].map(lambda values: not wanted.isdisjoint(values)).to_numpy()
    if year_range:
        years = to_float_array(df["Year"])
        in_range = (years >= year_range[0]) & (years <= year_range[1])  # NaN -> False
        mask &= in_range | (np.isnan(years) & include_undated)
    return df[mask]


def coverage(df: pd.DataFrame, col: str, exclude=NOT_RANKED) -> int:
    """Number of incidents that have at least one usable (non-excluded) value in `col`."""
    if df.empty:
        return 0
    return int(df[col + LIST_SUFFIX].map(lambda vs: any(v not in exclude for v in vs)).sum())


# ----------------------------------------------------------------------------- time
def incidents_per_year(df: pd.DataFrame) -> pd.DataFrame:
    dated = df.dropna(subset=["Year"])
    if dated.empty:
        return pd.DataFrame(columns=["Year", "incidents"])
    counts = dated["Year"].astype(int).value_counts()
    full_range = range(int(counts.index.min()), int(counts.index.max()) + 1)
    counts = counts.reindex(full_range, fill_value=0).sort_index()  # years with 0 records stay visible
    return counts.rename_axis("Year").reset_index(name="incidents")


def incidents_per_month(df: pd.DataFrame) -> pd.DataFrame:
    dated = df.dropna(subset=["YearMonth"])
    if dated.empty:
        return pd.DataFrame(columns=["YearMonth", "incidents"])
    counts = dated["YearMonth"].value_counts().sort_index()
    return counts.rename_axis("YearMonth").reset_index(name="incidents")


def mean_intensity_per_year(df: pd.DataFrame) -> pd.DataFrame:
    dated = df.dropna(subset=["Year"])
    if dated.empty:
        return pd.DataFrame(columns=["Year", "mean_weighted_intensity"])
    grouped = dated.assign(Year=dated["Year"].astype(int)).groupby("Year")["weighted_intensity"].mean()
    return grouped.round(2).rename("mean_weighted_intensity").reset_index()


def category_by_year(df: pd.DataFrame, col: str, top_k=5, exclude=NOT_RANKED) -> pd.DataFrame:
    """Year x category table of incident counts for the top_k categories."""
    dated = df.dropna(subset=["Year"])
    if dated.empty:
        return pd.DataFrame()
    exploded = dated[col + LIST_SUFFIX].explode().rename("value")
    pairs = dated["Year"].astype(int).to_frame().join(exploded)
    pairs = pairs[~pairs["value"].isin(exclude)]
    if pairs.empty:
        return pd.DataFrame()
    keep = pairs["value"].value_counts().head(top_k).index
    pairs = pairs[pairs["value"].isin(keep)]
    table = pd.crosstab(pairs["Year"].to_numpy(), pairs["value"].to_numpy())
    table.index.name, table.columns.name = "Year", None
    return table.reindex(columns=[v for v in keep if v in table.columns])


# ----------------------------------------------------------------------------- relationships
def cross_counts(df, col_a, col_b, top_a=10, top_b=10, exclude_a=NOT_RANKED, exclude_b=NOT_RANKED):
    """Matrix of incidents per (value of col_a, value of col_b); each incident once per pair."""
    if df.empty:
        return pd.DataFrame()
    a_values = df[col_a + LIST_SUFFIX].explode().rename("a")
    b_values = df[col_b + LIST_SUFFIX].explode().rename("b")
    pairs = a_values.to_frame().join(b_values)          # per incident: all (a, b) combinations
    pairs = pairs[~pairs["a"].isin(exclude_a) & ~pairs["b"].isin(exclude_b)]
    if pairs.empty:
        return pd.DataFrame()
    keep_a = pairs["a"].value_counts().head(top_a).index
    keep_b = pairs["b"].value_counts().head(top_b).index
    pairs = pairs[pairs["a"].isin(keep_a) & pairs["b"].isin(keep_b)]
    matrix = pd.crosstab(pairs["a"].to_numpy(), pairs["b"].to_numpy())
    return matrix.reindex(index=[v for v in keep_a if v in matrix.index],
                          columns=[v for v in keep_b if v in matrix.columns])


def mean_by_category(df, col, value_col="weighted_intensity", min_count=5, exclude=NOT_RANKED):
    """Average of a numeric column per category (categories with fewer than min_count incidents hidden)."""
    if df.empty:
        return pd.DataFrame(columns=["value", "mean", "incidents"])
    pairs = df[[value_col]].join(df[col + LIST_SUFFIX].explode().rename("value"))
    pairs = pairs[~pairs["value"].isin(exclude)]
    grouped = pairs.groupby("value")[value_col].agg(["mean", "count"]).reset_index()
    grouped = grouped[grouped["count"] >= min_count].rename(columns={"count": "incidents"})
    grouped["mean"] = grouped["mean"].round(2)
    return grouped.sort_values("mean", ascending=False).reset_index(drop=True)


# ----------------------------------------------------------------------------- effects
def classify_occurrence(values: list) -> str:
    """Recorded / None recorded / Not available for fields like disruption or data_theft."""
    if any(v != MISSING and v.lower() != "none" for v in values):
        return "Recorded"
    if any(v.lower() == "none" for v in values):
        return "None recorded"
    return MISSING


def occurrence_table(df: pd.DataFrame, fields: dict) -> pd.DataFrame:
    """Rows = field labels, columns = Recorded / None recorded / Not available (incident counts)."""
    statuses = ["Recorded", "None recorded", MISSING]
    rows = {}
    for label, col in fields.items():
        classified = df[col + LIST_SUFFIX].map(classify_occurrence)
        rows[label] = classified.value_counts().reindex(statuses, fill_value=0)
    return pd.DataFrame(rows).T[statuses]


def data_theft_summary(df: pd.DataFrame) -> dict:
    """Counts used by KPIs/insights: recorded, known (recorded + none) and total incidents."""
    if df.empty:
        return {"recorded": 0, "known": 0, "total": 0}
    classified = df["data_theft" + LIST_SUFFIX].map(classify_occurrence)
    recorded = int((classified == "Recorded").sum())
    known = int((classified != MISSING).sum())
    return {"recorded": recorded, "known": known, "total": len(df)}


def distribution_of_numeric(df: pd.DataFrame, col: str) -> pd.DataFrame:
    counts = pd.to_numeric(df[col], errors="coerce").dropna().astype(int).value_counts().sort_index()
    return counts.rename_axis("value").reset_index(name="incidents")


# ----------------------------------------------------------------------------- economic impact
def economic_category_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Counts per economic_impact category. Blank and 'Not available' stay separate from '0'."""
    counts = df["economic_impact"].value_counts()
    return counts.rename_axis("value").reset_index(name="incidents")


def economic_value_by_currency(df: pd.DataFrame) -> pd.DataFrame:
    """Per-currency summary of economic_impact_value > 0. Currencies are NEVER added together."""
    columns = ["currency", "incidents_with_value", "median_value", "max_value"]
    values = pd.to_numeric(df["economic_impact_value"], errors="coerce")
    known_currency = ~df["economic_impact_currency"].isin([MISSING])
    subset = df[(values > 0) & known_currency].assign(value=values)
    if subset.empty:
        return pd.DataFrame(columns=columns)
    grouped = subset.groupby("economic_impact_currency")["value"].agg(["count", "median", "max"])
    grouped = grouped.reset_index()
    grouped.columns = columns
    return grouped


# ----------------------------------------------------------------------------- attribution & response
def attribution_status(df: pd.DataFrame) -> pd.DataFrame:
    """Does the recorded initiator country name a country, or is it unknown / not attributed?"""
    def status(values):
        if any(v not in NOT_RANKED_INITIATOR for v in values):
            return "Initiator country recorded"
        if "Not attributed" in values:
            return "Not attributed"
        if "Unknown" in values:
            return "Unknown"
        return MISSING
    counts = df["initiator_country" + LIST_SUFFIX].map(status).value_counts()
    return counts.rename_axis("value").reset_index(name="incidents")


def response_presence(df: pd.DataFrame) -> dict:
    """Incidents with at least one recorded political / legal response (from number_* fields)."""
    return {
        "political": int((pd.to_numeric(df["number_political_responses"], errors="coerce") > 0).sum()),
        "legal": int((pd.to_numeric(df["number_legal_responses"], errors="coerce") > 0).sum()),
        "total": len(df),
    }


def responses_by_year(df: pd.DataFrame) -> pd.DataFrame:
    dated = df.dropna(subset=["Year"])
    if dated.empty:
        return pd.DataFrame()
    flags = pd.DataFrame({
        "Year": dated["Year"].astype(int),
        "Political response recorded": pd.to_numeric(dated["number_political_responses"], errors="coerce") > 0,
        "Legal response recorded": pd.to_numeric(dated["number_legal_responses"], errors="coerce") > 0,
    })
    return flags.groupby("Year").sum().astype(int)


# ----------------------------------------------------------------------------- dataset facts
def date_coverage(df: pd.DataFrame) -> dict:
    valid = df["start_date_parsed"].dropna()
    return {
        "first": valid.min() if len(valid) else None,
        "last": valid.max() if len(valid) else None,
        "valid": int(len(valid)),
        "invalid": int(len(df) - len(valid)),
    }


def missing_summary(raw: pd.DataFrame) -> pd.DataFrame:
    """Per column: blank cells + literal 'Not available' in the ORIGINAL workbook data."""
    text = raw.astype("string")
    missing = text.isna() | text.apply(lambda col: col.str.strip().str.lower().isin(["not available", ""]))
    summary = pd.DataFrame({"column": raw.columns, "missing_or_not_available": missing.sum().to_numpy()})
    summary["share_pct"] = np.round(summary["missing_or_not_available"] / len(raw) * 100, 1)
    return summary.sort_values("missing_or_not_available", ascending=False).reset_index(drop=True)
