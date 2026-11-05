

import time
import joblib
import pandas as pd
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "canary_dataset.csv"
MODEL_FILE = PROJECT_DIR / "ml" / "canary_model.pkl"

FEATURES = [
    "modifications",
    "renames",
    "deletions",
    "activity_rate",
]


def main():
    data = pd.read_csv(DATA_FILE)

    # Train only on normal activity.
    normal_data = data[data["label"] == 0]

    train_normal, held_out_normal = train_test_split(
        normal_data,
        test_size=0.25,
        random_state=42,
    )

    suspicious_data = data[data["label"] == 1]

    # Test on held-out normal and suspicious examples.
    test_data = pd.concat(
        [held_out_normal, suspicious_data],
        ignore_index=True,
    ).sample(frac=1, random_state=42).reset_index(drop=True)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=42,
    )

    model.fit(train_normal[FEATURES])

    # Measure prediction time for the complete test batch.
    start_time = time.perf_counter()
    raw_predictions = model.predict(test_data[FEATURES])
    total_prediction_time = time.perf_counter() - start_time

    predicted = (raw_predictions == -1).astype(int)
    actual = test_data["label"].astype(int)

    tn, fp, fn, tp = confusion_matrix(
        actual,
        predicted,
        labels=[0, 1],
    ).ravel()

    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

    joblib.dump(model, MODEL_FILE)

    print("\n=== CANARY ML Evaluation ===")
    print(f"Normal training records: {len(train_normal)}")
    print(f"Test records: {len(test_data)}")
    print(f"Model saved: {MODEL_FILE}")

    print("\nConfusion matrix:")
    print("[[TN, FP], [FN, TP]]")
    print([[int(tn), int(fp)], [int(fn), int(tp)]])

    print("\nMetrics for SUSPICIOUS activity:")
    print(f"Precision: {precision_score(actual, predicted, zero_division=0):.3f}")
    print(f"Recall:    {recall_score(actual, predicted, zero_division=0):.3f}")
    print(f"F1-score:  {f1_score(actual, predicted, zero_division=0):.3f}")
    print(f"False-positive rate: {false_positive_rate:.3f}")

    print("\nFull classification report:")
    print(
        classification_report(
            actual,
            predicted,
            target_names=["Normal", "Suspicious"],
            zero_division=0,
        )
    )

    print("\nPrediction timing:")
    print(f"Total test-batch prediction time: {total_prediction_time * 1000:.3f} ms")
    print(f"Average per record: {total_prediction_time / len(test_data) * 1000:.4f} ms")
    print("Timing is for batch inference only, not end-to-end live detection.")


if __name__ == "__main__":
    main()
