"""Cleaning layer: missing-value handling, multi-valued fields and dates.

Strategy
- Blank cells and the text "Not available" both become the explicit label MISSING.
  They are never converted into a real category and the raw data is kept untouched.
- Multi-valued cells ("A;B" or "A;A") are split into a list of DISTINCT values stored in
  a companion column "<name>__list". An incident counts once per distinct value.
"""
import re

import numpy as np
import pandas as pd

MISSING = "Not available"
BLANK_ECONOMIC = "Blank (no category recorded)"
NON_ATTRIBUTED = ("Not attributed", "Unknown")
LIST_SUFFIX = "__list"

# Categorical columns that get a "<name>__list" companion column.
LIST_COLUMNS = [
    "incident_type", "receiver_country", "receiver_regions", "receiver_category",
    "receiver_subcategory", "receiver_name", "initiator_country", "initiator_category",
    "initiator_subcategory", "initiator_name", "mitre_initial_access", "mitre_impact",
    "impact_indicator_label", "functional_impact", "intelligence_impact",
    "affected_entities", "affected_third_countries", "state_responsibility_actor",
    "response_indicator", "cyber_conflict_issue", "offline_conflict_name",
    "political_response_type", "legal_response_type", "attribution_basis",
    "attributing_country", "disruption", "data_theft", "hijacking", "zero_days",
    "user_interaction",
]

DATE_COLUMNS = ["start_date", "end_date", "attribution_date", "political_response_date",
                "legal_response_date", "added_to_db", "updated_at"]


def _split_outside_parentheses(text: str) -> list:
    """Split on ';' but not inside (...) because some labels contain ';' in brackets."""
    parts, depth, current = [], 0, []
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        if char == ";" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def split_values(cell, bracket_list: bool = False) -> list:
    """Return the distinct, cleaned values of one cell (MISSING if nothing usable)."""
    if cell is None or (not isinstance(cell, str) and pd.isna(cell)):
        return [MISSING]
    text = str(cell).strip()
    if bracket_list:  # receiver_regions looks like "['EUROPE', 'EU'];['EUROPE', 'EU']"
        tokens = re.findall(r"'([^']+)'", text) or [text]
    else:
        tokens = _split_outside_parentheses(text)
    cleaned = []
    for token in tokens:
        token = token.strip()
        if not token or token.lower() == MISSING.lower():
            token = MISSING
        cleaned.append(token)
    return list(dict.fromkeys(cleaned)) or [MISSING]


def parse_date_column(series: pd.Series) -> pd.Series:
    """Parse text dates (dd.mm.yyyy or yyyy-mm-dd). Unparseable values become NaT.
    Only the first date is used when a cell holds several ';'-separated dates."""
    if pd.api.types.is_datetime64_any_dtype(series):
        return series
    first = series.astype("string").str.split(";").str[0].str.strip()
    day_first = pd.to_datetime(first, format="%d.%m.%Y", errors="coerce")
    iso = pd.to_datetime(first, format="%Y-%m-%d", errors="coerce")
    return day_first.fillna(iso)


def _is_text_column(series: pd.Series) -> bool:
    return not (pd.api.types.is_numeric_dtype(series) or pd.api.types.is_bool_dtype(series)
                or pd.api.types.is_datetime64_any_dtype(series))


def clean_dataset(raw: pd.DataFrame) -> pd.DataFrame:
    """Return a cleaned COPY of the raw data (all 85 original columns are kept)."""
    df = raw.copy()

    for col in df.columns:
        if _is_text_column(df[col]):
            text = df[col].astype("string").str.strip()
            fill = BLANK_ECONOMIC if col == "economic_impact" else MISSING
            # economic_impact: true blanks are kept distinct from the text "Not available"
            text = text.fillna(fill).replace("", fill)
            df[col] = text.astype(object)

    # Dates: keep the original text, add parsed companions.
    for col in DATE_COLUMNS:
        if col in raw.columns:
            df[col + "_parsed"] = parse_date_column(raw[col])

    start = df["start_date_parsed"]
    df["Year"] = start.dt.year.astype("Int64")
    df["Month"] = start.dt.month.astype("Int64")
    df["YearMonth"] = start.dt.to_period("M").astype("string").where(start.notna())

    # Build all list columns at once (avoids a fragmented DataFrame).
    list_columns = {
        col + LIST_SUFFIX: df[col].map(
            lambda value, c=col: split_values(value, bracket_list=(c == "receiver_regions")))
        for col in LIST_COLUMNS if col in df.columns
    }
    df = pd.concat([df, pd.DataFrame(list_columns, index=df.index)], axis=1)
    return df


def to_float_array(series: pd.Series) -> np.ndarray:
    """Nullable integer/float series -> float array with NaN for missing."""
    return pd.to_numeric(series, errors="coerce").to_numpy(dtype="float64", na_value=np.nan)
