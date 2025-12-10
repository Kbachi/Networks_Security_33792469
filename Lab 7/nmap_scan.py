import nmap


def nmap_scan(host: str, port_range: str = "1-1024") -> None:
    """
    Use python-nmap to run an Nmap scan with service/version detection (-sV).
    Only run on localhost or explicitly authorized hosts.
    """
    nm = nmap.PortScanner()

    try:
        print(f"[*] Scanning {host} on ports {port_range} with -sV ...")
        nm.scan(host, port_range, arguments="-sV")  # -sV for service version detection

        for h in nm.all_hosts():
            print(f"\nHost:  {h} ({nm[h].hostname()})")
            print(f"State: {nm[h].state()}")

            for proto in nm[h].all_protocols():
                print(f"\nProtocol: {proto}")
                lport = nm[h][proto].keys()

                for port in sorted(lport):
                    service = nm[h][proto][port]
                    state = service.get("state", "unknown")
                    name = service.get("name", "unknown")
                    version = service.get("version", "")
                    print(f"Port: {port}\tState: {state}\tService: {name} {version}")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    host = input("Enter host (default 127.0.0.1): ").strip() or "127.0.0.1"
    port_range = input("Enter port range (default 1-100): ").strip() or "1-100"
    nmap_scan(host, port_range)
