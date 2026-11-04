"""Small Streamlit UI helpers (cards, notes, safe chart rendering)."""
import html

import matplotlib.pyplot as plt
import streamlit as st


def esc(value) -> str:
    return html.escape(str(value))


def section_header(title: str, subtitle: str = "") -> None:
    st.markdown(f'<div class="section-head"><h2>{esc(title)}</h2><p>{esc(subtitle)}</p></div>',
                unsafe_allow_html=True)


def kpi_cards(items: list) -> None:
    """items: list of (label, value, caption). Only valid KPIs should be passed in."""
    if not items:
        return
    for column, (label, value, caption) in zip(st.columns(len(items)), items):
        column.markdown(
            f'<div class="kpi-card"><div class="kpi-label">{esc(label)}</div>'
            f'<div class="kpi-value">{esc(value)}</div><div class="kpi-caption">{esc(caption)}</div></div>',
            unsafe_allow_html=True)


def insight_cards(insights: list) -> None:
    """insights: list of (title, headline, caption), shown two per row."""
    for start in range(0, len(insights), 2):
        for column, (title, headline, caption) in zip(st.columns(2), insights[start:start + 2]):
            column.markdown(
                f'<div class="insight-card"><div class="insight-title">{esc(title)}</div>'
                f'<div class="insight-headline">{esc(headline)}</div>'
                f'<div class="insight-caption">{esc(caption)}</div></div>',
                unsafe_allow_html=True)


def note(text: str) -> None:
    st.markdown(f'<div class="note">{esc(text)}</div>', unsafe_allow_html=True)


def show_figure(builder, *args, caption: str = "", **kwargs) -> None:
    """Build a chart inside a bordered card; a failing chart never crashes the page."""
    with st.container(border=True):
        try:
            fig = builder(*args, **kwargs)
            st.pyplot(fig)
            plt.close(fig)
        except Exception:
            st.warning("This chart could not be generated for the current selection.")
        if caption:
            st.caption(caption)


def exclusion_caption(df_len: int, usable: int, what: str) -> str:
    """Honest note about incidents left out of a ranking because the value is unavailable."""
    if usable >= df_len:
        return ""
    return f"{df_len - usable:,} of {df_len:,} incidents have no usable {what} and are excluded from this chart."
