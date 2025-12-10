import random
from typing import Set, List

# Simulation parameters

NUM_HOSTS = 50              # total number of hosts
ATTEMPTS_PER_INFECTED = 3   # how many infection attempts each infected host makes per step
MAX_STEPS = 20              # maximum number of time steps to simulate


def simulate_worm() -> None:
    # Represent hosts as numbers 0..NUM_HOSTS-1
    hosts: List[int] = list(range(NUM_HOSTS))

    # Start with a single infected host
    infected: Set[int] = {0}

    print(f"Step 0: infected = {len(infected)} hosts ({sorted(infected)})")


    for step in range(1, MAX_STEPS + 1):
        newly_infected: Set[int] = set()


        for host in infected:
            for _ in range(ATTEMPTS_PER_INFECTED):
                target = random.choice(hosts)  # randomly pick another host

                if target not in infected:
                    newly_infected.add(target)

        infected |= newly_infected

        print(
            f"Step {step}: infected = {len(infected)} hosts "
            f"({sorted(infected)})"
        )

        # If everyone is infected, stop early
        if len(infected) == NUM_HOSTS:
            print(f"All {NUM_HOSTS} hosts infected by step {step}. Stopping simulation.")
            break


if __name__ == "__main__":
    simulate_worm()
    print("Worm simulation complete.")