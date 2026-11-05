
import csv
import random
from pathlib import Path

random.seed(42)

OUTPUT_FILE = Path(__file__).resolve().parent / "canary_dataset.csv"

NORMAL_RECORDS = 800
SUSPICIOUS_RECORDS = 200


def create_record(
    modifications,
    renames,
    deletions,
    duration,
    decoy_triggered,
    label,
    scenario,
):
    total_events = modifications + renames + deletions

    return {
        "modifications": modifications,
        "renames": renames,
        "deletions": deletions,
        "activity_rate": round(total_events / max(duration, 0.1), 3),
        "elapsed_time_seconds": round(duration, 2),
        "decoy_triggered": decoy_triggered,
        "scenario": scenario,
        "label": label,
    }


def generate_normal_record():
    scenario = random.choice([
        "ordinary_editing",
        "bulk_edit",
        "file_organization",
        "busy_work_session",
    ])

    if scenario == "ordinary_editing":
        modifications = random.randint(0, 5)
        renames = random.randint(0, 2)
        deletions = random.randint(0, 1)
        duration = random.uniform(5, 30)

    elif scenario == "bulk_edit":
        # Normal activity can sometimes affect many files.
        modifications = random.randint(8, 30)
        renames = random.randint(0, 5)
        deletions = random.randint(0, 3)
        duration = random.uniform(5, 25)

    elif scenario == "file_organization":
        modifications = random.randint(0, 5)
        renames = random.randint(3, 15)
        deletions = random.randint(0, 3)
        duration = random.uniform(5, 30)

    else:
        modifications = random.randint(3, 15)
        renames = random.randint(0, 6)
        deletions = random.randint(0, 2)
        duration = random.uniform(3, 15)

    return create_record(
        modifications,
        renames,
        deletions,
        duration,
        decoy_triggered=0,
        label=0,
        scenario=scenario,
    )


def generate_suspicious_record():
    scenario = random.choice([
        "rapid_modifications",
        "mass_renaming",
        "mixed_file_activity",
        "decoy_interaction",
        "low_and_slow_activity",
    ])

    decoy_triggered = 0

    if scenario == "rapid_modifications":
        modifications = random.randint(10, 45)
        renames = random.randint(0, 8)
        deletions = random.randint(0, 5)
        duration = random.uniform(1, 8)

    elif scenario == "mass_renaming":
        modifications = random.randint(2, 15)
        renames = random.randint(8, 25)
        deletions = random.randint(0, 5)
        duration = random.uniform(2, 12)

    elif scenario == "mixed_file_activity":
        modifications = random.randint(5, 30)
        renames = random.randint(2, 12)
        deletions = random.randint(1, 8)
        duration = random.uniform(2, 15)

    elif scenario == "decoy_interaction":
        modifications = random.randint(0, 12)
        renames = random.randint(0, 5)
        deletions = random.randint(0, 3)
        duration = random.uniform(2, 15)
        decoy_triggered = 1

    else:
        # Some suspicious examples resemble ordinary activity.
        modifications = random.randint(3, 12)
        renames = random.randint(0, 4)
        deletions = random.randint(0, 2)
        duration = random.uniform(8, 25)

    return create_record(
        modifications,
        renames,
        deletions,
        duration,
        decoy_triggered=decoy_triggered,
        label=1,
        scenario=scenario,
    )


def main():
    records = []

    records.extend(
        generate_normal_record()
        for _ in range(NORMAL_RECORDS)
    )
    records.extend(
        generate_suspicious_record()
        for _ in range(SUSPICIOUS_RECORDS)
    )

    random.shuffle(records)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)

    print("Improved CANARY dataset generated.")
    print(f"Total records: {len(records)}")
    print(f"Normal records: {NORMAL_RECORDS}")
    print(f"Suspicious records: {SUSPICIOUS_RECORDS}")
    print("Normal scenarios include bulk editing and file organization.")
    print("Suspicious scenarios include overlapping and decoy-related activity.")
    print(f"Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

