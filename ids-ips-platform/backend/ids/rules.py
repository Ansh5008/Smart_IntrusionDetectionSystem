"""IDS detection rules — threshold and composite."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ThresholdRule:
    name: str
    metric: str  # packets_per_src_ip | unique_ports_per_src_ip | syn_count_per_dst_port
    window_seconds: int
    threshold: int
    severity: str  # Low | Medium | High | Critical
    attack_type: str


@dataclass
class CompositeRule:
    name: str
    conditions: list[str]
    severity: str
    attack_type: str


RULES: dict[str, ThresholdRule | CompositeRule] = {
    "ddos": ThresholdRule(
        name="ddos",
        metric="packets_per_src_ip",
        window_seconds=10,
        threshold=100,
        severity="Critical",
        attack_type="DDoS Flood",
    ),
    "port_scan": ThresholdRule(
        name="port_scan",
        metric="unique_ports_per_src_ip",
        window_seconds=30,
        threshold=20,
        severity="High",
        attack_type="Port Scan",
    ),
    "brute_force": ThresholdRule(
        name="brute_force",
        metric="syn_count_per_dst_port",
        window_seconds=60,
        threshold=30,
        severity="High",
        attack_type="Brute Force",
    ),
    "data_exfil": CompositeRule(
        name="data_exfil",
        conditions=["payload_entropy > 7.0", "size_bytes > 40000"],
        severity="Critical",
        attack_type="Data Exfiltration",
    ),
}

COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080, 8443}
