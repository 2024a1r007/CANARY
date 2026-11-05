# 🛡️ CANARY – Ransomware Early-Warning System

CANARY is a behavior-based cybersecurity prototype that monitors file activity to identify potentially suspicious patterns and generate early-warning alerts.

### Features
- File activity monitoring using Watchdog.
- Rolling-window risk scoring.
- Decoy-file detection and alerts.
- FastAPI backend and SQLite database.
- Streamlit security dashboard.
- Isolation Forest-based anomaly detection (offline evaluation).

### Tech Stack
Python | FastAPI | SQLite | Streamlit | Watchdog | Pandas | Scikit-learn

### Future Scope
- Integrate ML into live monitoring.
- Compare behavior-based, decoy-based, and hybrid detection.
- Improve detection accuracy and reduce false positives.
- Add performance reports and session-based filtering.

**Note:** This is an academic prototype tested using dummy files and synthetic data, not production-grade ransomware protection.
