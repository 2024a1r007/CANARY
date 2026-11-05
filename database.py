
import requests
import pandas as pd
import streamlit as st

API_BASE_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="CANARY Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CANARY Security Dashboard")
st.caption(
    "Behavior-based file monitoring and ransomware early-warning prototype"
)

# Fetch data through FastAPI, not directly from SQLite.
@st.cache_data(ttl=3)
def fetch_summary():
    response = requests.get(
        f"{API_BASE_URL}/summary",
        timeout=5
    )
    response.raise_for_status()
    return response.json()


@st.cache_data(ttl=3)
def fetch_events(limit):
    response = requests.get(
        f"{API_BASE_URL}/events",
        params={"limit": limit},
        timeout=5
    )
    response.raise_for_status()
    return response.json()


# Refresh button
if st.button("🔄 Refresh dashboard"):
    st.cache_data.clear()

try:
    summary = fetch_summary()
    event_data = fetch_events(500)

except requests.RequestException:
    st.error(
        "Cannot connect to the CANARY API. "
        "Start the backend with: python -m uvicorn api:app --reload"
    )
    st.stop()


# Overview metrics
st.subheader("Security Overview")

risk_counts = summary["risk_levels"]

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", summary["total_events"])
col2.metric("High Risk", risk_counts.get("HIGH", 0))
col3.metric("Medium Risk", risk_counts.get("MEDIUM", 0))
col4.metric("Low Risk", risk_counts.get("LOW", 0))

st.divider()

# Recent alerts
events = event_data["events"]
df = pd.DataFrame(events)

st.subheader("Recent Alerts")

if df.empty:
    st.info("No events recorded yet. Start the monitor and modify a test file.")

else:
    high_risk = df[df["risk_level"] == "HIGH"]
    decoy_events = df[
        df["event_type"].str.contains(
            "decoy", case=False, na=False
        )
    ]

    alert_col1, alert_col2 = st.columns(2)

    with alert_col1:
        if not high_risk.empty:
            st.warning(
                f"{len(high_risk)} stored event(s) have HIGH risk labels. "
                "Review the event history."
            )
        else:
            st.success("No HIGH-labelled events in the retrieved records.")

    with alert_col2:
        if not decoy_events.empty:
            st.error(
                f"{len(decoy_events)} decoy-related event(s) recorded."
            )
        else:
            st.info("No decoy-related events found in the retrieved records.")

    # Risk distribution
    st.subheader("Risk-Level Distribution")

    chart_data = (
        df["risk_level"]
        .value_counts()
        .reindex(["LOW", "MEDIUM", "HIGH"], fill_value=0)
    )

    st.bar_chart(chart_data)

    # Searchable event history
    st.subheader("Security Event History")

    search_text = st.text_input(
        "Search by event, file path, or risk level"
    )

    filtered_df = df.copy()

    if search_text:
        search_mask = filtered_df.astype(str).apply(
            lambda column: column.str.contains(
                search_text,
                case=False,
                na=False
            )
        ).any(axis=1)

        filtered_df = filtered_df[search_mask]

    display_columns = [
        "id",
        "event_time",
        "event_type",
        "file_path",
        "risk_points",
        "total_score",
        "risk_level"
    ]

    st.dataframe(
        filtered_df[display_columns],
        use_container_width=True,
        hide_index=True
    )

st.divider()

st.caption(
    "CANARY is a prototype. Risk labels are heuristic indicators, "
    "not confirmation of a ransomware infection. "
    "Dashboard alerts do not automatically block or delete files."
)

