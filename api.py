
from pathlib import Path
from datetime import datetime
import sqlite3

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


# ------------------------------------------
# 1. Create the FastAPI application
# ------------------------------------------

app = FastAPI(
    title="CANARY Security API",
    description=(
        "Backend API for CANARY, a behavior-based "
        "file monitoring and early-warning prototype."
    ),
    version="1.0.0"
)


# ------------------------------------------
# 2. Database configuration
# ------------------------------------------

DATABASE_FILE = Path(__file__).resolve().parent / "canary.db"


def get_connection():
    """Connect to the CANARY SQLite database."""
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


# ------------------------------------------
# 3. Validate incoming event data
# ------------------------------------------

class EventInput(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    file_path: str = Field(min_length=1, max_length=1000)
    risk_points: int = Field(ge=0, le=100)
    total_score: int = Field(ge=0, le=100000)
    risk_level: str


# ------------------------------------------
# 4. Home endpoint
# ------------------------------------------

@app.get("/")
def home():
    return {
        "project": "CANARY",
        "message": "Security API is running",
        "version": "1.0.0"
    }


# ------------------------------------------
# 5. Health-check endpoint
# ------------------------------------------

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "database_exists": DATABASE_FILE.exists()
    }


# ------------------------------------------
# 6. Save a new security event
# ------------------------------------------

@app.post("/events", status_code=201)
def create_event(event: EventInput):

    if not DATABASE_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="CANARY database not found. Run database.py first."
        )

    allowed_levels = {"LOW", "MEDIUM", "HIGH"}

    if event.risk_level not in allowed_levels:
        raise HTTPException(
            status_code=400,
            detail="Risk level must be LOW, MEDIUM, or HIGH."
        )

    event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO security_events (
                    event_time,
                    event_type,
                    file_path,
                    risk_points,
                    total_score,
                    risk_level
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_time,
                    event.event_type,
                    event.file_path,
                    event.risk_points,
                    event.total_score,
                    event.risk_level
                )
            )

            new_id = cursor.lastrowid

    except sqlite3.Error as error:
        raise HTTPException(
            status_code=500,
            detail="Could not save the security event."
        ) from error

    return {
        "message": "Security event saved successfully",
        "event_id": new_id,
        "event_time": event_time
    }


# ------------------------------------------
# 7. Retrieve security events
# ------------------------------------------

@app.get("/events")
def get_events(limit: int = 50):

    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 500."
        )

    if not DATABASE_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="CANARY database not found."
        )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                event_time,
                event_type,
                file_path,
                risk_points,
                total_score,
                risk_level
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    return {
        "count": len(rows),
        "events": [dict(row) for row in rows]
    }


# ------------------------------------------
# 8. Get risk summary
# ------------------------------------------

@app.get("/summary")
def get_summary():

    if not DATABASE_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="CANARY database not found."
        )

    with get_connection() as connection:

        total_events = connection.execute(
            "SELECT COUNT(*) FROM security_events"
        ).fetchone()[0]

        risk_counts = connection.execute(
            """
            SELECT risk_level, COUNT(*) AS total
            FROM security_events
            GROUP BY risk_level
            """
        ).fetchall()

    summary = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0
    }

    for row in risk_counts:
        if row["risk_level"] in summary:
            summary[row["risk_level"]] = row["total"]

    return {
        "total_events": total_events,
        "risk_levels": summary
    }

