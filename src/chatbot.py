"""EuRepoC Cyber Threat Intelligence AI Assistant powered by Groq.

Provides interactive, strictly grounded intelligence analysis based exclusively
on the recorded incidents in the EuRepoC dataset.
"""
import os
import re
from pathlib import Path
from typing import Generator, List, Dict, Any

import pandas as pd
import streamlit as st
from groq import Groq, AuthenticationError, APIError, RateLimitError

from src import analysis as A
from src.data_cleaning import MISSING, NON_ATTRIBUTED

DEFAULT_MODEL = "qwen/qwen3.8-27b"
FALLBACK_MODELS = ["qwen/qwen3.8-27b", "llama-3.3-70b-versatile", "llama-3.1-8b-instant"]
SECRETS_FILE = Path(__file__).resolve().parent.parent / ".streamlit" / "secrets.toml"

STOPWORDS = {
    "what", "when", "where", "which", "who", "whom", "this", "that", "these",
    "those", "have", "from", "with", "about", "against", "between", "into",
    "through", "during", "before", "after", "above", "below", "some", "such",
    "only", "same", "than", "too", "very", "can", "will", "just", "should",
    "now", "tell", "show", "many", "much", "incident", "incidents", "data",
    "dataset", "please", "cyber", "attack", "attacks", "threat", "threats"
}


def get_groq_api_key() -> str:
    """Retrieve Groq API key from session state, environment, or secrets."""
    # 1. Session state (user entered via UI)
    if st.session_state.get("groq_api_key"):
        return st.session_state["groq_api_key"].strip()

    # 2. Environment variable
    env_key = os.environ.get("GROQ_API_KEY", "").strip()
    if env_key:
        return env_key

    # 3. Streamlit secrets
    try:
        if hasattr(st, "secrets") and "GROQ_API_KEY" in st.secrets:
            sec_key = str(st.secrets["GROQ_API_KEY"]).strip()
            if sec_key:
                return sec_key
    except Exception:
        pass

    # 4. Read .streamlit/secrets.toml directly if exists
    if SECRETS_FILE.exists():
        try:
            content = SECRETS_FILE.read_text(encoding="utf-8")
            match = re.search(r'GROQ_API_KEY\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                return match.group(1).strip()
        except Exception:
            pass

    return ""


def save_groq_api_key_to_file(key: str) -> bool:
    """Save API key to .streamlit/secrets.toml for persistence."""
    try:
        SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if SECRETS_FILE.exists():
            existing = SECRETS_FILE.read_text(encoding="utf-8").splitlines()
            lines = [l for l in existing if not l.strip().startswith("GROQ_API_KEY")]
        lines.append(f'GROQ_API_KEY = "{key.strip()}"')
        SECRETS_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True
    except Exception:
        return False


@st.cache_data
def get_dataset_ground_truth(_df: pd.DataFrame) -> str:
    """Compute verified factual ground-truth metrics for the system prompt."""
    total = len(_df)
    years = _df["Year"].dropna().astype(int)
    year_min = int(years.min()) if not years.empty else 2000
    year_max = int(years.max()) if not years.empty else 2024
    undated_count = int(_df["Year"].isna().sum())

    disruption = int(_df["has_disruption"].sum()) if "has_disruption" in _df.columns else 0
    theft = A.data_theft_summary(_df)
    intensity_mean = _df["weighted_intensity"].dropna().mean() if "weighted_intensity" in _df.columns else 0.0

    top_rcv = A.count_values(_df, "receiver_country", top_n=8)
    top_rcv_str = ", ".join([f"{r.value} ({r.incidents:,} / {r.share_pct}%)" for _, r in top_rcv.iterrows()])

    top_init = A.count_values(_df, "initiator_country", exclude=A.NOT_RANKED_INITIATOR, top_n=8)
    top_init_str = ", ".join([f"{r.value} ({r.incidents:,} / {r.share_pct}%)" for _, r in top_init.iterrows()])

    top_types = A.count_values(_df, "incident_type", top_n=8)
    top_types_str = ", ".join([f"{r.value} ({r.incidents:,})" for _, r in top_types.iterrows()])

    top_cat = A.count_values(_df, "receiver_category", top_n=6)
    top_cat_str = ", ".join([f"{r.value} ({r.incidents:,})" for _, r in top_cat.iterrows()])

    top_mitre_init = A.count_values(_df, "mitre_initial_access", top_n=6)
    top_mitre_init_str = ", ".join([f"{r.value} ({r.incidents:,})" for _, r in top_mitre_init.iterrows()])

    top_mitre_imp = A.count_values(_df, "mitre_impact", top_n=6)
    top_mitre_imp_str = ", ".join([f"{r.value} ({r.incidents:,})" for _, r in top_mitre_imp.iterrows()])

    non_attr_count = len(_df[_df["initiator_country"].astype(str).str.contains("Not attributed|Unknown", case=False, na=False)])

    return f"""### GLOBAL DATASET GROUND TRUTH (EuRepoC Workbook):
- Total Recorded Incidents: {total:,}
- Timeline Range: {year_min} to {year_max} ({undated_count} incidents have no verified start date)
- Incidents with Disruption: {disruption:,} ({disruption / total * 100:.1f}%)
- Incidents with Data Theft: {theft['recorded']:,} (among {theft['known']:,} records with data theft information)
- Average Weighted Intensity: {intensity_mean:.2f}
- Attribution Reality: {non_attr_count:,} incidents are "Not attributed" or "Unknown" initiator.
- Top Receiver Countries: {top_rcv_str}
- Top Attributed Initiator Countries: {top_init_str}
- Top Incident Types: {top_types_str}
- Top Targeted Categories: {top_cat_str}
- Top MITRE Initial Access: {top_mitre_init_str}
- Top MITRE Impact: {top_mitre_imp_str}
- Special Notes: Casualties field is unrecorded (empty) across all records in this dataset. Economic impact is reported in mixed currencies (EUR, USD) and must never be summed across currencies.
"""


def search_relevant_incidents(df: pd.DataFrame, query: str, limit: int = 4) -> List[Dict[str, Any]]:
    """Dynamically search the dataset for incidents matching query terms."""
    terms = [
        t.lower() for t in re.findall(r"\w+", query)
        if len(t) > 2 and t.lower() not in STOPWORDS
    ]
    if not terms:
        return []

    mask = pd.Series(False, index=df.index)
    searchable_cols = ["name", "description", "receiver_country", "initiator_country",
                       "initiator_name", "incident_type", "receiver_name"]

    for col in searchable_cols:
        if col in df.columns:
            col_text = df[col].astype(str).str.lower()
            for term in terms:
                mask |= col_text.str.contains(re.escape(term), na=False)

    matches = df[mask].head(limit)
    records = []
    for _, row in matches.iterrows():
        desc = str(row.get("description", ""))
        if len(desc) > 240:
            desc = desc[:237] + "..."
        records.append({
            "id": row.get("incident_id", "N/A"),
            "name": row.get("name", "N/A"),
            "date": str(row.get("start_date", "Unknown")),
            "receiver": str(row.get("receiver_country", "Unknown")),
            "initiator": str(row.get("initiator_country", "Unknown")),
            "type": str(row.get("incident_type", "Unknown")),
            "summary": desc,
        })
    return records


def build_system_prompt(df: pd.DataFrame, user_query: str) -> str:
    """Assemble strict system prompt with dataset ground truth and live matches."""
    ground_truth = get_dataset_ground_truth(df)
    matching_incidents = search_relevant_incidents(df, user_query, limit=4)

    incident_context = ""
    if matching_incidents:
        incident_context = "\n### SPECIFIC INCIDENTS RETRIEVED FROM DATASET MATCHING QUERY:\n"
        for inc in matching_incidents:
            incident_context += (
                f"- [Incident ID: {inc['id']}] {inc['name']}\n"
                f"  * Start Date: {inc['date']} | Target: {inc['receiver']} | Initiator: {inc['initiator']}\n"
                f"  * Type: {inc['type']}\n"
                f"  * Brief: {inc['summary']}\n"
            )

    return f"""You are the EuRepoC AI Cyber Threat Intelligence Analyst for the Global Cybercrime Analysis & Intelligence Dashboard.

### STRICT SCOPE & OPERATIONAL BOUNDARIES:
1. PROJECT-ONLY CONSTRAINT: You MUST answer questions solely based on this project and the recorded incidents in the EuRepoC dataset.
   - If the user asks ANY question unrelated to this cyber intelligence project (such as general knowledge, programming outside this app, math, recipes, casual conversation, or external world events outside cyber incidents), you MUST politely refuse:
     "I am strictly designated to answer questions about the Global Cybercrime Analysis & Intelligence Dashboard and its recorded EuRepoC incidents. Please ask a question related to cyber incidents, threat actors, targets, or attack patterns in this dataset."
2. FACTUAL ACCURACY:
   - Ground all statistics, numbers, and facts strictly in the dataset metrics provided below.
   - NEVER hallucinate cyber incident numbers, dates, groups, or casualties.
   - Remember that 'casualties' is not available for any record in this dataset.
   - Clarify that non-attributed/unknown initiators represent a large portion of incidents.
3. CTI BRIEFING TONE:
   - Professional, objective, crisp, and analytical.
   - Use Markdown formatting, bullet points, and bold metric callouts.

{ground_truth}
{incident_context}
"""


def stream_groq_response(api_key: str, model: str, messages: List[Dict[str, str]]) -> Generator[str, None, None]:
    """Stream completion chunks from Groq API with automatic model fallback."""
    client = Groq(api_key=api_key)
    models_to_try = [model] + [m for m in FALLBACK_MODELS if m != model]
    last_err = None

    for target_model in models_to_try:
        try:
            stream = client.chat.completions.create(
                model=target_model,
                messages=messages,
                temperature=0.2,
                max_tokens=1024,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
            return
        except Exception as e:
            last_err = e
            if "model_not_found" in str(e) or "does not exist" in str(e):
                continue
            raise e

    if last_err:
        raise last_err


def init_chat_state():
    """Ensure session state variables for chat are initialized."""
    if "chat_messages" not in st.session_state:
        st.session_state["chat_messages"] = [
            {
                "role": "assistant",
                "content": (
                    "Greetings Analyst. I am your **EuRepoC Cyber Intelligence AI Assistant**, "
                    "powered by Groq. I am strictly specialized in analyzing the **3,414 recorded cyber incidents** "
                    "in this dataset—including threat actors, attack vectors, targets, MITRE techniques, "
                    "and geopolitical responses.\n\n"
                    "How can I assist your investigation today?"
                ),
            }
        ]


def render_chat_widget(df: pd.DataFrame, is_dialog: bool = False):
    """Render the full chat interface with API key manager and quick prompts."""
    init_chat_state()
    api_key = get_groq_api_key()

    st.markdown(
        """
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom: 0.6rem;">
            <div>
                <span class="chat-analyst-badge">🛡️ EUREPOC INTEL AI</span>
                <span style="font-size:0.8rem; color:#94a3b8; margin-left:8px;">Project-Grounded Analyst</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # API Key Configuration section
    if not api_key:
        st.warning("🔑 **Groq API Key Required to Activate AI Analyst**")
        st.markdown(
            "Please provide your Groq API key to start chatting. You can generate a free key instantly at "
            "[console.groq.com/keys](https://console.groq.com/keys)."
        )
        col_in, col_btn = st.columns([3, 1])
        with col_in:
            key_input = st.text_input(
                "Enter Groq API Key",
                type="password",
                placeholder="gsk_...",
                label_visibility="collapsed",
                key="groq_key_field",
            )
        with col_btn:
            save_file = st.checkbox("Save permanently", value=True, help="Saves to .streamlit/secrets.toml")
            if st.button("Connect AI", key="connect_groq_btn"):
                if key_input.strip():
                    st.session_state["groq_api_key"] = key_input.strip()
                    if save_file:
                        save_groq_api_key_to_file(key_input.strip())
                    st.success("Groq API Key saved successfully!")
                    st.rerun()
                else:
                    st.error("Please enter a valid key starting with 'gsk_'")
        st.info("💡 You can also set `export GROQ_API_KEY=\"your-key\"` in your terminal anytime.")
        return

    # Status Bar & Controls
    col_status, col_clear = st.columns([3, 1])
    with col_status:
        st.markdown(
            f"<div style='font-size:0.82rem; color:#22d3ee; padding-top:4px;'>"
            f"🟢 <b>AI Analyst Active</b> &nbsp;|&nbsp; 3,414 Incidents Loaded</div>",
            unsafe_allow_html=True,
        )
    with col_clear:
        if st.button("🗑️ Clear Chat", key=f"clear_chat_{'dialog' if is_dialog else 'page'}"):
            st.session_state["chat_messages"] = []
            st.rerun()

    # Quick Prompts
    st.markdown("<div style='font-size:0.75rem; color:#64748b; margin-top:0.4rem;'>QUICK INTELLIGENCE PROMPTS:</div>", unsafe_allow_html=True)
    qp_cols = st.columns(4)
    quick_query = None
    if qp_cols[0].button("📊 Top 5 Targets", key=f"qp1_{is_dialog}"):
        quick_query = "What are the top 5 most targeted countries in the dataset and their share?"
    if qp_cols[1].button("🕵️ Top Initiators", key=f"qp2_{is_dialog}"):
        quick_query = "Which initiator nations are most frequently recorded and what is the attribution distribution?"
    if qp_cols[2].button("⚡ Disruption & Theft", key=f"qp3_{is_dialog}"):
        quick_query = "What proportion of attacks caused disruption versus data theft?"
    if qp_cols[3].button("🛡️ MITRE Vectors", key=f"qp4_{is_dialog}"):
        quick_query = "What are the most frequent MITRE initial access and impact techniques?"

    # Display chat history
    chat_container = st.container(height=380 if is_dialog else 460)
    with chat_container:
        for msg in st.session_state["chat_messages"]:
            avatar = "🛡️" if msg["role"] == "assistant" else "👤"
            with st.chat_message(msg["role"], avatar=avatar):
                st.markdown(msg["content"])

    # Handle Input (either from quick prompt or chat_input)
    user_prompt = st.chat_input("Ask a question about the EuRepoC cyber incidents...", key=f"chat_input_{is_dialog}")
    active_prompt = quick_query or user_prompt

    if active_prompt:
        # Add user message
        st.session_state["chat_messages"].append({"role": "user", "content": active_prompt})

        with chat_container:
            with st.chat_message("user", avatar="👤"):
                st.markdown(active_prompt)

            with st.chat_message("assistant", avatar="🛡️"):
                # Construct Groq messages
                system_prompt = build_system_prompt(df, active_prompt)
                api_messages = [{"role": "system", "content": system_prompt}]
                # include last 6 messages for context
                for m in st.session_state["chat_messages"][-6:]:
                    api_messages.append({"role": m["role"], "content": m["content"]})

                try:
                    response_text = st.write_stream(
                        stream_groq_response(api_key, DEFAULT_MODEL, api_messages)
                    )
                    st.session_state["chat_messages"].append(
                        {"role": "assistant", "content": response_text}
                    )
                except AuthenticationError as e:
                    st.error(f"Authentication Failed: Invalid Groq API Key. ({e})")
                except RateLimitError as e:
                    st.warning(f"Groq Rate Limit Exceeded: Please wait a moment. ({e})")
                except APIError as e:
                    st.error(f"Groq API Error: {e}")
                except Exception as e:
                    st.error(f"Unexpected Error: {type(e).__name__} - {e}")


@st.dialog("🛡️ EuRepoC Cyber Intelligence AI Analyst", width="large")
def render_chat_dialog(df: pd.DataFrame):
    """Render the chatbot within an interactive Streamlit modal dialog."""
    render_chat_widget(df, is_dialog=True)


def render_chat_page(df: pd.DataFrame):
    """Render the chatbot as a dedicated section in the dashboard."""
    from src.ui import section_header
    section_header(
        "AI Cyber Analyst",
        "Interactive intelligence analyst powered by Groq (llama-3.3-70b-versatile), strictly grounded in the EuRepoC dataset."
    )
    render_chat_widget(df, is_dialog=False)
