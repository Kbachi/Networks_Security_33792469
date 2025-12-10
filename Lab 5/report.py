import os
import glob
import webbrowser

# Must match the -o name you used in the wapiti command
OUT_NAME = "gruyere_report.html"

def find_html_report(out_name: str) -> str | None:
    """Locate the Wapiti HTML report and return its absolute path, or None."""
    # Direct file path
    if os.path.isfile(out_name) and out_name.lower().endswith(".html"):
        return os.path.abspath(out_name)

    # Directory containing HTMLs
    if os.path.isdir(out_name):
        candidates = glob.glob(os.path.join(out_name, "*.html"))
        if candidates:
            candidates.sort(key=os.path.getmtime, reverse=True)
            return os.path.abspath(candidates[0])

    # Fallback: newest HTML in current folder
    candidates = glob.glob("*.html")
    if candidates:
        candidates.sort(key=os.path.getmtime, reverse=True)
        return os.path.abspath(candidates[0])

    return None


def main() -> None:
    report_path = find_html_report(OUT_NAME)

    if not report_path:
        print(
            "No HTML report found.\n"
            "Check that Wapiti created an HTML file and that OUT_NAME matches it."
        )
        return

    print(f"Report file found: {report_path}")
    print("Opening in your default web browser...")
    webbrowser.open_new_tab(report_path)

