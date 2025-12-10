import csv
import hashlib
from pathlib import Path

#reformattting the path to stay in the folder
FOLDER_TO_SCAN = Path(__file__).parent
BASELINE_CSV = FOLDER_TO_SCAN / "baseline.csv"


#hash
def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# baseline 
def load_baseline():
    baseline = {}
    with BASELINE_CSV.open("r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            baseline[row["filename"]] = row["sha256"]
    return baseline


#check
def check_for_changes():
    baseline = load_baseline()

    
    current_hashes = {}
    for entry in FOLDER_TO_SCAN.iterdir():
        if entry.is_file() and entry.name != "baseline.csv":
            current_hashes[entry.name] = sha256_file(entry)

    
    for filename, old_hash in baseline.items():
        if filename not in current_hashes:
            print(f"[DELETED] {filename} is missing from folder.")
        else:
            new_hash = current_hashes[filename]
            if old_hash != new_hash:
                print(f"[MODIFIED] {filename} hash changed!")
            else:
                print(f"[OK] {filename} unchanged.")

    for filename in current_hashes:
        if filename not in baseline:
            print(f"[NEW] {filename} was added since baseline.")


if __name__ == "__main__":
    check_for_changes()
    print("Integrity check complete.")
    