import os
import hashlib
import csv
from datetime import datetime
from pathlib import Path

FOLDER_TO_SCAN = Path(__file__).parent      # folder with files
BASELINE_CSV = FOLDER_TO_SCAN /("baseline.csv")      # output baseline file


def sha256_file(path: Path) -> str:
    """Return SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def create_baseline() -> None:
    """Scan folder and create baseline.csv with filename, hash, timestamp."""
    with BASELINE_CSV.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["filename", "sha256", "timestamp"])

        for entry in FOLDER_TO_SCAN.iterdir():
            if entry.is_file():
                file_hash = sha256_file(entry)
                timestamp = datetime.now().isoformat()
                writer.writerow([entry.name, file_hash, timestamp])
                print(f"Hashed {entry.name}")

    print(f"Baseline written to {BASELINE_CSV}")


if __name__ == "__main__":
    create_baseline()
    print("Integrity baseline creation complete.")