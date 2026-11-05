
import sqlite3
from pathlib import Path

database_file = Path(__file__).resolve().parent / "canary.db"

connection = sqlite3.connect(database_file)
cursor = connection.cursor()

cursor.execute("""
    SELECT id, event_time, event_type, file_path,
           risk_points, total_score, risk_level
    FROM security_events
    ORDER BY id DESC
    LIMIT 10
""")

events = cursor.fetchall()

print("\n===== CANARY DATABASE RECORDS =====")

if events:
    for event in events:
        print("\nID:", event[0])
        print("Time:", event[1])
        print("Event:", event[2])
        print("File:", event[3])
        print("Points added:", event[4])
        print("Total score:", event[5])
        print("Risk level:", event[6])
else:
    print("No events found.")

connection.close()
