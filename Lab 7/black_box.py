import requests


def black_box_recon(url: str) -> None:
    """
    Perform a simple black-box recon by sending an HTTP HEAD request
    and printing key response headers.

    Use only on your own sites or those you have permission to test.
    """
    try:
        response = requests.head(url, timeout=5)
        print("=== Black Box Findings ===")
        print(f"Status code: {response.status_code}")
        print(f"Server:       {response.headers.get('Server', 'Unknown')}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    url = input("Enter a URL (e.g. http://127.0.0.1:8000): ").strip()
    black_box_recon(url)
