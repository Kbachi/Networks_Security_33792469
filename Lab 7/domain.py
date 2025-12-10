import socket
import requests


def get_domain_info(domain: str) -> None:
    """
    Resolve a domain name to an IP address and fetch public WHOIS-like info
    using the ipapi.co API.

    Only use on domains you own or are explicitly allowed to test.
    """
    try:
        # Get IP address (active but low-risk)
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip}")

        # Get public WHOIS-like info (passive, using a free API)
        url = f"https://ipapi.co/{ip}/json/"
        print(f"[+] Fetching info from: {url}")
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            print(f"Organization: {data.get('org', 'Unknown')}")
            print(f"City:        {data.get('city', 'Unknown')}")
            print(f"Country:     {data.get('country_name', 'Unknown')}")
        else:
            print(f"[-] Could not fetch WHOIS data (status {response.status_code}).")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    # Example: replace with a domain you are allowed to inspect
    domain = input("Enter a domain (e.g. example.com): ").strip()
    get_domain_info(domain)
