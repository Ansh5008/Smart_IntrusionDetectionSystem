"""Realistic network packet generator."""
from __future__ import annotations
import random
from datetime import datetime
from models.packet import Packet

COUNTRIES = ["US", "CN", "RU", "DE", "BR", "IN", "KR", "JP", "GB", "FR", "IR", "UA", "NG", "VN", "PK"]
PROTOCOLS: list[str] = ["TCP", "UDP", "ICMP"]
COMMON_PORTS = [80, 443, 22, 3306, 8080, 53, 25, 110, 3389, 445, 8443, 5432, 1433, 21, 23]
FLAG_SETS = {
    "TCP": [["SYN"], ["SYN", "ACK"], ["ACK"], ["FIN", "ACK"], ["RST"], ["PSH", "ACK"]],
    "UDP": [[]],
    "ICMP": [[]],
}


def _rand_ip(prefix: str = "") -> str:
    if prefix:
        parts = prefix.split(".")
        while len(parts) < 4:
            parts.append(str(random.randint(1, 254)))
        return ".".join(parts[:4])
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_normal_packet() -> Packet:
    proto = random.choices(PROTOCOLS, weights=[70, 25, 5])[0]
    dst_port = random.choices(COMMON_PORTS, weights=[25, 30, 5, 3, 5, 8, 2, 1, 2, 2, 3, 2, 1, 1, 1])[0]
    return Packet(
        timestamp=datetime.utcnow(),
        src_ip=_rand_ip(),
        dst_ip=_rand_ip("10.0"),
        src_port=random.randint(1024, 65535),
        dst_port=dst_port,
        protocol=proto,
        size_bytes=random.randint(40, 1500),
        ttl=random.choice([64, 128, 255]),
        flags=random.choice(FLAG_SETS[proto]),
        payload_entropy=round(random.uniform(1.0, 5.0), 2),
        geo_country=random.choices(COUNTRIES, weights=[20, 10, 8, 7, 5, 5, 4, 4, 6, 5, 3, 3, 3, 2, 2])[0],
        is_flagged=False,
    )


def generate_ddos_packet(target_ip: str = "10.0.1.100", attacker_ip: str | None = None) -> Packet:
    src = attacker_ip or _rand_ip()
    return Packet(
        timestamp=datetime.utcnow(),
        src_ip=src, dst_ip=target_ip,
        src_port=random.randint(1024, 65535), dst_port=80,
        protocol="TCP", size_bytes=random.randint(40, 100),
        ttl=random.choice([32, 64]), flags=["SYN"],
        payload_entropy=round(random.uniform(0.5, 2.0), 2),
        geo_country=random.choice(["CN", "RU", "IR", "KR"]),
        is_flagged=True,
    )


def generate_port_scan_packet(scanner_ip: str = "185.220.101.42") -> Packet:
    return Packet(
        timestamp=datetime.utcnow(),
        src_ip=scanner_ip, dst_ip=_rand_ip("10.0"),
        src_port=random.randint(1024, 65535),
        dst_port=random.randint(1, 65535),
        protocol="TCP", size_bytes=random.randint(40, 60),
        ttl=64, flags=["SYN"],
        payload_entropy=round(random.uniform(0.1, 1.0), 2),
        geo_country="RU", is_flagged=True,
    )


def generate_brute_force_packet(target_port: int = 22) -> Packet:
    return Packet(
        timestamp=datetime.utcnow(),
        src_ip=_rand_ip("45.33"),
        dst_ip=_rand_ip("10.0"),
        src_port=random.randint(1024, 65535), dst_port=target_port,
        protocol="TCP", size_bytes=random.randint(60, 150),
        ttl=64, flags=["SYN"],
        payload_entropy=round(random.uniform(2.0, 4.0), 2),
        geo_country=random.choice(["CN", "RU", "VN"]),
        is_flagged=True,
    )


def generate_exfil_packet() -> Packet:
    return Packet(
        timestamp=datetime.utcnow(),
        src_ip=_rand_ip("10.0"),
        dst_ip=_rand_ip(),
        src_port=random.randint(1024, 65535),
        dst_port=random.randint(8000, 9999),
        protocol="TCP", size_bytes=random.randint(40000, 120000),
        ttl=128, flags=["PSH", "ACK"],
        payload_entropy=round(random.uniform(7.2, 7.99), 2),
        geo_country=random.choice(["RU", "CN", "IR"]),
        is_flagged=True,
    )
