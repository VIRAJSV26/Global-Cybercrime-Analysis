"""Matplotlib charts in a consistent dark, cybersecurity-style theme.

Each function receives already-calculated tables and returns a Figure (never calls Streamlit).
"""
import matplotlib

matplotlib.use("Agg")  # no display needed; Streamlit renders the figure
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap

BG = "#111a2e"        # matches the dashboard card background
GRID = "#243049"
TEXT = "#cbd5e1"
MUTED = "#8b9bb4"
CYAN = "#22d3ee"
INDIGO = "#818cf8"
AMBER = "#fbbf24"
ROSE = "#fb7185"
GREEN = "#34d399"
SERIES_COLORS = [CYAN, INDIGO, AMBER, ROSE, GREEN, "#f472b6", "#a3e635", "#94a3b8"]
HEAT_CMAP = LinearSegmentedColormap.from_list("intel", ["#0f1a2e", "#0e7490", CYAN])


# ----------------------------------------------------------------------------- helpers
def shorten_labels(labels, limit=44) -> list:
    """Readable, unique axis labels: cut long definitions at the first ' (' then truncate."""
    labels = [str(label) for label in labels]
    short = []
    for label in labels:
        text = label
        if len(text) > limit and " (" in text:
            text = text.split(" (")[0]
        if len(text) > limit:
            text = text[: limit - 1].rstrip() + "…"
        short.append(text)
    for i, text in enumerate(short):          # collisions -> fall back to longer truncation
        if short.count(text) > 1:
            short[i] = labels[i][:70].rstrip() + ("…" if len(labels[i]) > 70 else "")
    seen = {}
    for i, text in enumerate(short):          # last resort: number duplicates
        seen[text] = seen.get(text, 0) + 1
        if seen[text] > 1:
            short[i] = f"{text} ({seen[text]})"
    return short


def _new_figure(width=7.6, height=4.2):
    fig, ax = plt.subplots(figsize=(width, height), dpi=110)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(colors=TEXT, labelsize=8.5, length=0)
    return fig, ax


def _finish(fig, ax, title, xlabel=None, ylabel=None):
    ax.set_title(title, loc="left", color="#f1f5f9", fontsize=11.5, fontweight="bold", pad=12)
    if xlabel:
        ax.set_xlabel(xlabel, color=MUTED, fontsize=9)
    if ylabel:
        ax.set_ylabel(ylabel, color=MUTED, fontsize=9)
    fig.tight_layout()
    return fig


def empty_figure(message="No data available for this selection."):
    fig, ax = _new_figure(7.6, 2.4)
    ax.axis("off")
    ax.text(0.5, 0.5, message, ha="center", va="center", color=MUTED, fontsize=10, transform=ax.transAxes)
    return fig


def _is_empty(data) -> bool:
    return data is None or len(data) == 0


# ----------------------------------------------------------------------------- charts
def hbar(data: pd.DataFrame, label_col: str, value_col: str, title: str,
         xlabel="Recorded incidents", color=CYAN, pct_col=None):
    """Horizontal bar chart, largest bar on top, value labels at the bar ends."""
    if _is_empty(data):
        return empty_figure()
    data = data.reset_index(drop=True)
    labels = shorten_labels(data[label_col])
    values = data[value_col].to_numpy(dtype=float)
    fig, ax = _new_figure(7.6, max(2.6, 0.4 * len(data) + 1.3))
    positions = np.arange(len(data))
    ax.barh(positions, values, color=color, height=0.62, zorder=3)
    ax.set_yticks(positions)
    ax.set_yticklabels(labels, color=TEXT)
    ax.invert_yaxis()
    ax.xaxis.grid(True, color=GRID, linewidth=0.7, zorder=0)
    ax.set_xlim(0, values.max() * 1.22 if values.max() > 0 else 1)
    for pos, value, row in zip(positions, values, data.itertuples(index=False)):
        text = f"{value:,.0f}" if float(value).is_integer() else f"{value:,.2f}"
        if pct_col:
            text += f"  ({getattr(row, pct_col):.1f}%)"
        ax.text(value + values.max() * 0.015, pos, text, va="center", color=TEXT, fontsize=8)
    return _finish(fig, ax, title, xlabel)


def vbar(x, y, title, xlabel, ylabel="Recorded incidents", color=CYAN, highlight_max=True):
    """Vertical bar chart (e.g. incidents per year); the maximum bar is highlighted."""
    if _is_empty(x):
        return empty_figure()
    x, y = list(x), np.asarray(y, dtype=float)
    fig, ax = _new_figure(7.6, 4.0)
    colors = [color] * len(y)
    if highlight_max and y.max() > 0:
        colors[int(np.argmax(y))] = AMBER
    ax.bar(range(len(y)), y, color=colors, width=0.7, zorder=3)
    step = max(1, len(x) // 14)
    ax.set_xticks(range(0, len(x), step))
    ax.set_xticklabels([str(v) for v in x][::step], rotation=0 if len(x) <= 14 else 45, color=TEXT)
    ax.yaxis.grid(True, color=GRID, linewidth=0.7, zorder=0)
    if len(y) <= 12:
        for i, value in enumerate(y):
            ax.text(i, value, f"{value:,.0f}" if float(value).is_integer() else f"{value:.2f}",
                    ha="center", va="bottom", color=TEXT, fontsize=8)
    return _finish(fig, ax, title, xlabel, ylabel)


def line_chart(x, series: dict, title, xlabel, ylabel="Recorded incidents"):
    """One or more lines over a shared x axis (dict: label -> values)."""
    if _is_empty(x) or not series:
        return empty_figure()
    fig, ax = _new_figure(7.6, 4.0)
    for i, (label, values) in enumerate(series.items()):
        ax.plot(range(len(x)), np.asarray(values, dtype=float), marker="o" if len(x) <= 30 else None,
                markersize=3.5, linewidth=2, color=SERIES_COLORS[i % len(SERIES_COLORS)],
                label=shorten_labels([label], 34)[0])
    step = max(1, len(x) // 12)
    ax.set_xticks(range(0, len(x), step))
    ax.set_xticklabels([str(v) for v in x][::step], rotation=45 if len(x) > 12 else 0, color=TEXT)
    ax.yaxis.grid(True, color=GRID, linewidth=0.7)
    if len(series) > 1:
        legend = ax.legend(frameon=False, fontsize=8, loc="upper left")
        for text in legend.get_texts():
            text.set_color(TEXT)
    return _finish(fig, ax, title, xlabel, ylabel)


def heatmap(matrix: pd.DataFrame, title, xlabel, ylabel):
    """Count heatmap; zero cells are left blank so the pattern stays readable."""
    if _is_empty(matrix):
        return empty_figure()
    rows = shorten_labels(matrix.index, 38)
    cols = shorten_labels(matrix.columns, 22)
    values = matrix.to_numpy(dtype=float)
    fig, ax = _new_figure(7.6, max(3.2, 0.42 * len(rows) + 2.6))
    ax.imshow(values, cmap=HEAT_CMAP, aspect="auto", vmin=0)
    ax.set_xticks(range(len(cols)))
    ax.set_xticklabels(cols, rotation=40, ha="right", color=TEXT)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(rows, color=TEXT)
    threshold = values.max() * 0.55
    for i in range(values.shape[0]):
        for j in range(values.shape[1]):
            if values[i, j] > 0:
                ax.text(j, i, f"{values[i, j]:,.0f}", ha="center", va="center", fontsize=7.5,
                        color="#04121c" if values[i, j] > threshold else TEXT)
    return _finish(fig, ax, title, xlabel, ylabel)


def stacked_hbar(table: pd.DataFrame, title, xlabel="Incidents", colors=None):
    """Stacked horizontal bars: one row per index label, one segment per column."""
    if _is_empty(table):
        return empty_figure()
    colors = colors or SERIES_COLORS
    fig, ax = _new_figure(7.6, max(2.6, 0.75 * len(table) + 1.4))
    left = np.zeros(len(table))
    labels = shorten_labels(table.index, 30)
    for i, column in enumerate(table.columns):
        values = table[column].to_numpy(dtype=float)
        ax.barh(range(len(table)), values, left=left, color=colors[i % len(colors)], height=0.55,
                label=str(column), zorder=3)
        for j, value in enumerate(values):
            if value > 0 and value >= table.to_numpy().sum(axis=1).max() * 0.06:
                ax.text(left[j] + value / 2, j, f"{value:,.0f}", ha="center", va="center",
                        fontsize=8, color="#04121c")
        left += values
    ax.set_yticks(range(len(table)))
    ax.set_yticklabels(labels, color=TEXT)
    ax.invert_yaxis()
    ax.xaxis.grid(True, color=GRID, linewidth=0.7, zorder=0)
    legend = ax.legend(frameon=False, fontsize=8, ncol=len(table.columns), loc="lower center",
                       bbox_to_anchor=(0.5, -0.32))
    for text in legend.get_texts():
        text.set_color(TEXT)
    return _finish(fig, ax, title, xlabel)


def donut(data: pd.DataFrame, label_col: str, value_col: str, title):
    """Donut chart for a small number of categories (use bars when there are many)."""
    if _is_empty(data):
        return empty_figure()
    fig, ax = _new_figure(7.6, 3.8)
    values = data[value_col].to_numpy(dtype=float)
    labels = shorten_labels(data[label_col], 30)
    wedges, _ = ax.pie(values, colors=SERIES_COLORS[: len(values)], startangle=90, counterclock=False,
                       wedgeprops={"width": 0.42, "edgecolor": BG, "linewidth": 2})
    total = values.sum()
    legend = ax.legend(wedges, [f"{lab}: {val:,.0f} ({val / total * 100:.1f}%)" for lab, val in zip(labels, values)],
                       frameon=False, fontsize=8.5, loc="center left", bbox_to_anchor=(1.0, 0.5))
    for text in legend.get_texts():
        text.set_color(TEXT)
    ax.text(0, 0, f"{total:,.0f}", ha="center", va="center", color="#f1f5f9", fontsize=16, fontweight="bold")
    return _finish(fig, ax, title)
