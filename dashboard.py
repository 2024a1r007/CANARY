
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DATABASE_FILE = Path(__file__).resolve().parent / "canary.db"
EVALUATION_FILE = (
    Path(__file__).resolve().parent
    / "evaluation"
    / "ml_evaluation.csv"
)

st.set_page_config(
    page_title="CANARY Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ CANARY Security Dashboard")
st.caption(
    "Behavior-based file monitoring and early-warning prototype"
)

# --------------------------------------------------
# SECTION 1: LIVE SECURITY EVENTS
# --------------------------------------------------

st.header("1. Live Security Monitoring")

if not DATABASE_FILE.exists():
    st.error("Database not found. Run your existing monitor/API first.")
    st.stop()

try:
    with sqlite3.connect(DATABASE_FILE) as connection:
        df = pd.read_sql_query(
            """
            SELECT id, event_time, event_type, file_path,
                   risk_points, total_score, risk_level
            FROM security_events
            ORDER BY id DESC
            """,
            connection
        )
except Exception as error:
    st.error(f"Could not read security events: {error}")
    st.stop()

if df.empty:
    st.info(
        "No events recorded yet. Start the monitor and modify a test file."
    )
else:
    total_events = len(df)
    high_events = int((df["risk_level"] == "HIGH").sum())
    medium_events = int((df["risk_level"] == "MEDIUM").sum())
    low_events = int((df["risk_level"] == "LOW").sum())

    st.subheader("Security Overview")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", total_events)
    col2.metric("High-Risk Events", high_events)
    col3.metric("Medium-Risk Events", medium_events)
    col4.metric("Low-Risk Events", low_events)

    st.subheader("Risk-Level Distribution")

    risk_counts = (
        df["risk_level"]
        .value_counts()
        .reindex(["LOW", "MEDIUM", "HIGH"], fill_value=0)
    )
    st.bar_chart(risk_counts)

    st.subheader("Event History")

    search_text = st.text_input(
        "Search by event type, file path, or risk level"
    )

    filtered_df = df.copy()

    if search_text:
        matches = (
            filtered_df.astype(str)
            .apply(
                lambda column: column.str.contains(
                    search_text,
                    case=False,
                    na=False
                )
            )
            .any(axis=1)
        )
        filtered_df = filtered_df[matches]

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

st.divider()

# --------------------------------------------------
# SECTION 2: ML MODEL EVALUATION
# --------------------------------------------------

st.header("2. Machine Learning Evaluation")

st.write(
    "These metrics come from the latest saved synthetic-dataset "
    "evaluation. They are separate from live security-event counts."
)

# These are the actual results from your latest terminal output.
# They are shown as a fixed snapshot until a metrics file is generated.
col1, col2, col3, col4 = st.columns(4)

col1.metric("Precision", "81.3%")
col2.metric("Recall", "50.0%")
col3.metric("F1-Score", "0.619")
col4.metric("False-Positive Rate", "11.5%")

st.caption(
    "Evaluation snapshot: 400 test records, 177 true negatives, "
    "23 false positives, 100 false negatives, and 100 true positives."
)

st.subheader("Confusion Matrix")

confusion_df = pd.DataFrame(
    [[177, 23], [100, 100]],
    index=["Actual Normal", "Actual Suspicious"],
    columns=["Predicted Normal", "Predicted Suspicious"]
)

st.dataframe(confusion_df, use_container_width=True)

st.subheader("Model Prediction Time")

time_col1, time_col2 = st.columns(2)
time_col1.metric("Batch Prediction Time", "13.814 ms")
time_col2.metric("Average per Record", "0.0345 ms")

st.caption(
    "Timing measures batch model inference only. It excludes file "
    "monitoring, API communication, and dashboard refresh time."
)

st.warning(
    "Prototype limitation: these results use synthetic data. "
    "They do not establish real-world ransomware detection accuracy. "
    "The ML model has not yet been integrated into live monitoring."
)

st.divider()

st.header("3. Project Status")



st.caption(
    "A high risk score is a heuristic alert, not confirmation "
    "of a ransomware attack."
)

if st.button("Refresh dashboard"):
    st.rerun()

