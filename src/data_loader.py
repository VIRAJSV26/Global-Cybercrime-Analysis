"""Load and validate the EuRepoC Excel workbook (the only data source)."""
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_ROOT / "data" / "eurepoc_global_dataset_1_3.xlsx"
SHEET_NAME = "Global"
EXPECTED_COLUMN_COUNT = 85

# Every column the dashboard reads. If one is absent, the app stops with a clear message.
REQUIRED_COLUMNS = [
    "incident_id", "name", "description", "start_date", "end_date", "incident_type",
    "receiver_name", "receiver_country", "receiver_regions", "receiver_category",
    "receiver_subcategory", "initiator_name", "initiator_country", "initiator_category",
    "initiator_subcategory", "number_attributions", "attribution_date", "attribution_type",
    "attribution_basis", "attributing_country", "settled_initiator", "cyber_conflict_issue",
    "offline_conflict_issue", "offline_conflict_name", "number_political_responses",
    "political_response_date", "political_response_type", "political_response_subtype",
    "zero_days", "mitre_initial_access", "mitre_impact", "user_interaction", "has_disruption",
    "data_theft", "disruption", "hijacking", "unweighted_intensity", "target_multiplier",
    "weighted_intensity", "impact_indicator_label", "impact_indicator_score",
    "functional_impact", "intelligence_impact", "affected_entities", "affected_entities_value",
    "affected_third_countries", "affected_third_countries_value", "economic_impact",
    "economic_impact_value", "economic_impact_currency", "state_responsibility_actor",
    "evidence_for_sanctions_indicator", "number_legal_responses", "legal_response_date",
    "legal_response_type", "legal_response_subtype", "response_indicator", "casualties",
    "source_url", "added_to_db", "updated_at",
]


class DatasetError(Exception):
    """Raised with a user-friendly message when the dataset cannot be used."""


def load_raw_dataset(path=DATA_FILE, sheet_name=SHEET_NAME) -> pd.DataFrame:
    """Read the 'Global' sheet exactly as stored in the workbook (no cleaning)."""
    path = Path(path)
    if not path.exists():
        raise DatasetError(
            f"Dataset file not found: {path}. Place 'eurepoc_global_dataset_1_3.xlsx' "
            "inside the 'data' folder next to app.py."
        )
    try:
        workbook = pd.ExcelFile(path, engine="openpyxl")
    except Exception as exc:  # corrupted / not an xlsx file
        raise DatasetError(f"The workbook could not be opened ({type(exc).__name__}). "
                           "The file may be corrupted or is not a valid .xlsx file.") from exc
    try:
        if sheet_name not in workbook.sheet_names:
            raise DatasetError(f"Sheet '{sheet_name}' was not found. "
                               f"Sheets in this workbook: {workbook.sheet_names}")
        raw = workbook.parse(sheet_name)
    except DatasetError:
        raise
    except Exception as exc:
        raise DatasetError(f"Sheet '{sheet_name}' could not be read ({type(exc).__name__}).") from exc
    finally:
        workbook.close()
    if raw.empty:
        raise DatasetError(f"Sheet '{sheet_name}' contains no rows.")
    return raw


def validate_columns(raw: pd.DataFrame, required=REQUIRED_COLUMNS) -> None:
    """Stop with an explicit expected-vs-actual message when a required column is absent."""
    missing = [col for col in required if col not in raw.columns]
    if missing:
        raise DatasetError(
            f"Missing required column(s): {missing}.\n"
            f"Actual available columns: {list(raw.columns)}"
        )


def load_validated_dataset() -> pd.DataFrame:
    raw = load_raw_dataset()
    validate_columns(raw)
    return raw
