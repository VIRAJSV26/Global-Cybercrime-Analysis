# Global Cybercrime Analysis & Intelligence Dashboard

An interactive Streamlit dashboard that analyzes the **recorded cyber incidents** in the supplied
EuRepoC workbook `eurepoc_global_dataset_1_3.xlsx`. Every number and chart is calculated from that
file and updates with the filters. No data is invented, downloaded or simulated.

## 1. What the project does
It turns 3,414 incident records into global threat patterns, target and initiator analysis, MITRE
techniques, impact, attribution, responses, timelines and automatically generated insights.

## 2. Dataset
- File: `data/eurepoc_global_dataset_1_3.xlsx`, sheet **Global**, 3,414 rows x 85 columns.
- Start dates run from 2000 to 19 Dec 2024 (92 records have no valid start date).
- The workbook does not name an author or source, so none is claimed in the app.

## 3. Features
- 10 sections: Executive Overview, Threat Landscape, Attack & MITRE, Target & Initiator,
  Impact, Attribution & Geopolitical Response, Response Analysis, Timeline, Data Explorer, Methodology.
- Global filters (year, countries, incident type, categories, MITRE, impact, responses) and **RESET FILTERS**.
- KPI cards, live "Intelligence Insights", Matplotlib charts, searchable record table + CSV download.
- Careful handling of "Not available", multi-valued cells (`A;A;B`) and economic impact (never summed
  across euro and dollar, never treated as zero when missing).

## 4. Project structure
```
Global-Cybercrime-Dashboard/
├── app.py              # Streamlit entry point: layout, navigation, filters
├── requirements.txt
├── README.md
├── data/               # the Excel dataset
├── assets/style.css    # dark theme
├── .streamlit/config.toml
└── src/
    ├── data_loader.py      # read + validate the workbook
    ├── data_cleaning.py    # missing values, dates, multi-valued fields
    ├── analysis.py         # all Pandas/NumPy calculations
    ├── visualization.py    # Matplotlib charts
    ├── insights.py         # dynamic insight sentences
    ├── pages.py            # one function per dashboard section
    └── ui.py               # cards and chart containers
```

## 5. Installation (Python 3.11 or newer)
Windows:
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```
macOS / Linux:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 6. How to run
```
streamlit run app.py
```
Your browser opens at http://localhost:8501. Keep the Excel file inside the `data` folder.

## 7. Troubleshooting
- **"Dataset file not found"** - make sure `data/eurepoc_global_dataset_1_3.xlsx` exists next to `app.py`.
- **"Missing required column(s)"** - the Excel file was changed; the message lists expected vs actual columns.
- **`streamlit` is not recognized** - activate the virtual environment first, or run `python -m streamlit run app.py`.
- **Fonts look plain** - the Inter font loads from Google Fonts; offline, a system font is used instead.
- **"No incidents match the selected filters."** - press RESET FILTERS in the sidebar.

## 8. Dataset limitations
- The dashboard shows recorded incidents in this dataset only; it is not a count of all cyberattacks
  or verified global crime statistics, and it does not claim causation.
- Many fields are "Not available" (for example MITRE initial access is missing for most incidents,
  and `casualties` is missing for every record). These are excluded from rankings and stated on charts.
- Multi-valued fields count an incident once per distinct value, so category totals can exceed 100%.
- "Not attributed" / "Unknown" initiators are reported as such, never as findings about an actor.
