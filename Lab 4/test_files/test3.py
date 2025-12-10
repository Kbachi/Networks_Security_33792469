import re
from pathlib import Path

#  PATHS 
FOLDER_TO_SCAN = Path(__file__).parent

#  SIGNATURES
SIGNATURES = [
    r"eval\(",
    r"exec\(",
    r"base64\.b64decode",
    r"socket\.",
    r"subprocess\.",
    r"os\.system",
]


def scan_file(path: Path) -> None:
    """
    Scan a single file for any of the signatures.
    If a signature is found, print a warning.
    """
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        
        return

    hits = []

    for pattern in SIGNATURES:
        if re.search(pattern, content):
            hits.append(pattern)

    if hits:
        print(f"[SUSPICIOUS] {path.name} matched signatures:")
        for h in hits:
            print(f"   -> {h}")


def scan_folder() -> None:
    """
    Scan all relevant files in the folder for suspicious signatures.
    """
    for entry in FOLDER_TO_SCAN.iterdir():
        # Limit to certain extensions 
        if entry.is_file() and entry.suffix in {".py", ".txt"}:
            scan_file(entry)


if __name__ == "__main__":
    scan_folder()
    print("Scanning complete.")