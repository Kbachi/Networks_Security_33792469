import socket
from typing import List


def scan_ports(host: str, ports: List[int]) -> List[int]:
    """
    Very simple TCP port scanner using raw sockets.
    Only use on localhost or authorized hosts.
    """
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # seconds

        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)
            else:
                print(f"[-] Port {port} is CLOSED or FILTERED")
        except Exception as e:
            print(f"[!] Error on port {port}: {e}")
        finally:
            sock.close()

    return open_ports


if __name__ == "__main__":
    host = input("Enter host (default 127.0.0.1): ").strip() or "127.0.0.1"
    # Example set of ports to scan
    ports_to_scan = [22, 80, 443, 8080]

    print(f"Scanning {host} on ports {ports_to_scan} ...")
    open_ports = scan_ports(host, ports_to_scan)
    print(f"Open ports on {host}: {open_ports}")
