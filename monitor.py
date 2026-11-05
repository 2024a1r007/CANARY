
from pathlib import Path
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import time

TEST_FOLDER = Path("test_files").resolve()
DECOY_NAME = "canary_decoy.txt"
API_URL = "http://127.0.0.1:8000/events"

TIME_WINDOW_SECONDS = 10
EVENT_THRESHOLD = 10

RISK_POINTS = {
    "File modified": 1,
    "File renamed or moved": 2,
    "File deleted": 2,
    "Decoy file affected": 5,
}

# Each item stores: (time, points, event type, file path)
recent_events = deque()


def get_risk_level(score, rapid_activity=False, decoy_affected=False):
    if decoy_affected or score >= 6 or rapid_activity:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    return "LOW"


def send_event_to_api(event_type, file_path, points, score, level):
    data = {
        "event_type": event_type,
        "file_path": str(file_path),
        "risk_points": points,
        "total_score": score,
        "risk_level": level,
    }

    try:
        response = requests.post(API_URL, json=data, timeout=3)
        response.raise_for_status()
        print(f"API: Event saved (ID: {response.json()['event_id']})")
    except requests.RequestException as error:
        print(f"API ERROR: Event could not be saved: {error}")


class CanaryHandler(FileSystemEventHandler):

    def report_event(self, event_type, file_path):
        now = time.time()
        file_name = Path(file_path).name
        is_decoy = file_name == DECOY_NAME

        if is_decoy:
            stored_type = "Decoy file affected"
            points = RISK_POINTS[stored_type]
        else:
            stored_type = event_type
            points = RISK_POINTS.get(event_type, 0)

        recent_events.append((now, points, stored_type, str(file_path)))

        # Remove events older than the rolling 10-second window.
        while recent_events and now - recent_events[0][0] > TIME_WINDOW_SECONDS:
            recent_events.popleft()

        # Recalculate the score from recent activity only.
        current_score = sum(item[1] for item in recent_events)
        rapid_activity = len(recent_events) >= EVENT_THRESHOLD

        risk_level = get_risk_level(
            current_score,
            rapid_activity=rapid_activity,
            decoy_affected=is_decoy
        )

        print("\n========== CANARY EVENT ==========")
        print(f"Event: {stored_type}")
        print(f"File: {file_path}")
        print(f"Points added: +{points}")
        print(f"Recent risk score: {current_score}")
        print(f"Risk level: {risk_level}")
        print(f"Events in last 10 seconds: {len(recent_events)}")

        if is_decoy:
            print("ALERT: Decoy file activity detected.")

        if rapid_activity:
            print("ALERT: Rapid file activity detected. Investigate.")

        send_event_to_api(
            stored_type,
            file_path,
            points,
            current_score,
            risk_level
        )

        print("==================================")


    def on_modified(self, event):
        if not event.is_directory:
            self.report_event("File modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.report_event("File deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.report_event("File renamed or moved", event.src_path)


if __name__ == "__main__":
    TEST_FOLDER.mkdir(parents=True, exist_ok=True)

    observer = Observer()
    observer.schedule(CanaryHandler(), str(TEST_FOLDER), recursive=False)
    observer.start()

    print("CANARY behavior monitor started.")
    print(f"Watching: {TEST_FOLDER}")
    print("Risk score uses a rolling 10-second window.")
    print("Use only dummy files in this test folder.")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nCANARY monitoring stopped.")
    finally:
        observer.join()

