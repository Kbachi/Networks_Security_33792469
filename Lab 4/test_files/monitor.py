import random
from pathlib import Path
from typing import List

# ---------- PARAMETERS ----------
NUM_HOSTS = 20              # how many hosts in our "network"
STEPS = 30                  # how many time steps to simulate
SUSPICIOUS_THRESHOLD = 10   # > this number of connections = suspicious

# Put alerts.log in the same folder as this script
BASE_FOLDER = Path(__file__).parent
ALERT_LOG = BASE_FOLDER / "alerts.log"


def simulate_outbound_connections(num_hosts: int) -> List[int]:
    """
    Simulate outbound connection counts for each host.
    For simplicity, just return random integers.
    """
    # You can tweak the range to make alerts more/less frequent
    return [random.randint(0, 15) for _ in range(num_hosts)]


def log_alert(message: str) -> None:
    """
    Print the alert and append it to alerts.log.
    """
    print(message)
    with ALERT_LOG.open("a", encoding="utf-8") as f:
        f.write(message + "\n")


def monitor_network() -> None:
    """
    Main monitoring loop.
    At each step, simulate network activity and flag suspicious hosts.
    """
    # Clear old log at the start (optional)
    if ALERT_LOG.exists():
        ALERT_LOG.unlink()

    for step in range(1, STEPS + 1):
        # Simulate this step's outbound connections for each host
        connections = simulate_outbound_connections(NUM_HOSTS)

        # Check each host's count
        for host_id, count in enumerate(connections):
            if count > SUSPICIOUS_THRESHOLD:
                msg = (
                    f"[ALERT] Step {step}: Host {host_id} has "
                    f"{count} outbound connections "
                    f"(threshold={SUSPICIOUS_THRESHOLD})"
                )
                log_alert(msg)


if __name__ == "__main__":
    monitor_network()
    print(f"\nMonitoring complete. Alerts (if any) written to {ALERT_LOG.name}")
