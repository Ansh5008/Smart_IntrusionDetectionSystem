"""Attack scenario orchestrator — decides when to inject attacks."""
from __future__ import annotations
import random
from simulation.packet_generator import (
    generate_normal_packet, generate_ddos_packet,
    generate_port_scan_packet, generate_brute_force_packet,
    generate_exfil_packet,
)
from models.packet import Packet


class AttackScenario:
    """Weighted random attack injection."""

    def __init__(self):
        self._tick = 0
        self._ddos_burst_remaining = 0
        self._scan_burst_remaining = 0
        self._bf_burst_remaining = 0
        self._ddos_attacker = ""

    def next_batch(self, batch_size: int = 5) -> list[Packet]:
        self._tick += 1
        packets: list[Packet] = []

        # Handle ongoing bursts first
        if self._ddos_burst_remaining > 0:
            n = min(self._ddos_burst_remaining, batch_size)
            packets.extend(generate_ddos_packet(attacker_ip=self._ddos_attacker) for _ in range(n))
            self._ddos_burst_remaining -= n
            return packets

        if self._scan_burst_remaining > 0:
            n = min(self._scan_burst_remaining, batch_size)
            packets.extend(generate_port_scan_packet() for _ in range(n))
            self._scan_burst_remaining -= n
            return packets

        if self._bf_burst_remaining > 0:
            n = min(self._bf_burst_remaining, batch_size)
            packets.extend(generate_brute_force_packet() for _ in range(n))
            self._bf_burst_remaining -= n
            return packets

        # Roll for new attack (weighted)
        roll = random.random()
        if roll < 0.03:  # 3% chance DDoS burst
            self._ddos_burst_remaining = random.randint(80, 200)
            self._ddos_attacker = f"{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            packets.append(generate_ddos_packet(attacker_ip=self._ddos_attacker))
            self._ddos_burst_remaining -= 1
        elif roll < 0.07:  # 4% port scan
            self._scan_burst_remaining = random.randint(25, 60)
            packets.append(generate_port_scan_packet())
            self._scan_burst_remaining -= 1
        elif roll < 0.11:  # 4% brute force
            self._bf_burst_remaining = random.randint(35, 80)
            packets.append(generate_brute_force_packet())
            self._bf_burst_remaining -= 1
        elif roll < 0.13:  # 2% exfil
            packets.append(generate_exfil_packet())
        else:
            # Normal traffic
            packets.extend(generate_normal_packet() for _ in range(batch_size))

        return packets


scenario = AttackScenario()
