"""Dynamic insight sentences. Each one is computed from the CURRENTLY FILTERED data.

Wording is deliberately neutral: "recorded", "in this dataset" - never "most attacked in the world".
"""
import pandas as pd

from . import analysis as A


def _top_value(df, col, exclude=A.NOT_RANKED):
    """(value, incidents, share_pct) of the most frequent usable value, or None."""
    counts = A.count_values(df, col, exclude=exclude, top_n=1)
    if counts.empty:
        return None
    row = counts.iloc[0]
    return row["value"], int(row["incidents"]), float(row["share_pct"])


def _short(text: str, limit=60) -> str:
    text = text.split(" (")[0] if len(text) > limit else text
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _top_insight(df, col, title, exclude=A.NOT_RANKED, note_missing=True):
    top = _top_value(df, col, exclude)
    if top is None:
        return None
    value, count, share = top
    usable = A.coverage(df, col, exclude)
    caption = f"{count:,} incidents ({share:.1f}% of the {len(df):,} filtered incidents)."
    if note_missing and usable < len(df):
        caption += f" {len(df) - usable:,} incidents have no usable value for this field."
    return title, _short(value), caption


def generate_insights(df: pd.DataFrame) -> list:
    """Return a list of (title, headline, caption) tuples; fields without data are skipped."""
    if df.empty:
        return []
    insights = [
        _top_insight(df, "incident_type", "Most frequently recorded incident type"),
        _top_insight(df, "receiver_country", "Receiver country with the highest number of recorded incidents"),
        _top_insight(df, "initiator_country", "Most frequently recorded initiator country",
                     exclude=A.NOT_RANKED_INITIATOR),
        _top_insight(df, "mitre_initial_access", "Most common MITRE initial-access technique"),
        _top_insight(df, "mitre_impact", "Most common MITRE impact technique"),
        _top_insight(df, "functional_impact", "Most common functional impact"),
        _top_insight(df, "political_response_type", "Most common recorded political response type"),
        _top_insight(df, "legal_response_type", "Most common recorded legal response type"),
    ]

    by_year = A.incidents_per_year(df)
    if not by_year.empty and by_year["incidents"].max() > 0:
        peak = by_year.loc[by_year["incidents"].idxmax()]
        insights.append(("Year with the highest number of recorded incidents", str(int(peak["Year"])),
                         f"{int(peak['incidents']):,} incidents with a valid start date in this selection."))

    disruption = int(df["has_disruption"].sum())
    insights.append(("Incidents with recorded disruption", f"{disruption / len(df) * 100:.1f}%",
                     f"{disruption:,} of {len(df):,} filtered incidents (field: has_disruption)."))

    theft = A.data_theft_summary(df)
    if theft["known"] > 0:
        insights.append(("Incidents with recorded data theft", f"{theft['recorded'] / theft['known'] * 100:.1f}%",
                         f"{theft['recorded']:,} of {theft['known']:,} incidents that have data-theft information "
                         f"({theft['total'] - theft['known']:,} unavailable and excluded)."))

    intensity = A.mean_by_category(df, "incident_type", min_count=5)
    if not intensity.empty:
        best = intensity.iloc[0]
        insights.append(("Highest average weighted intensity by incident type", _short(best["value"]),
                         f"Average {best['mean']:.2f} across {int(best['incidents']):,} incidents "
                         "(types with fewer than 5 incidents ignored)."))
    return [item for item in insights if item is not None]
