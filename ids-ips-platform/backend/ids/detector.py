"""IDS detector — sliding window rule engine."""
from __future__ import annotations
import time
from collections import defaultdict
from models.packet import Packet
from models.alert import Alert
from ids.rules import RULES, ThresholdRule, CompositeRule, COMMON_PORTS
from ids.scorer import compute_severity, compute_confidence


class _SlidingWindow:
    def __init__(self, window_sec: int):
        self.window = window_sec
        self.events: list[float] = []

    def add(self, ts: float | None = None):
        self.events.append(ts or time.time())

    def count(self) -> int:
        cutoff = time.time() - self.window
        self.events = [t for t in self.events if t > cutoff]
        return len(self.events)


class Detector:
    def __init__(self):
        # key = (rule_name, src_ip) -> window
        self._pkt_windows: dict[tuple[str, str], _SlidingWindow] = defaultdict(
            lambda: _SlidingWindow(10)
        )
        # port scan tracking: src_ip -> set of dst_ports
        self._port_sets: dict[str, set[int]] = defaultdict(set)
        self._port_windows: dict[str, _SlidingWindow] = defaultdict(
            lambda: _SlidingWindow(30)
        )
        # brute force: (dst_port) -> syn count window
        self._syn_windows: dict[int, _SlidingWindow] = defaultdict(
            lambda: _SlidingWindow(60)
        )

    def analyze(self, packet: Packet) -> list[Alert]:
        alerts: list[Alert] = []
        now = time.time()

        # ── DDoS rule ──
        ddos = RULES["ddos"]
        if isinstance(ddos, ThresholdRule):
            key = ("ddos", packet.src_ip)
            if key not in self._pkt_windows:
                self._pkt_windows[key] = _SlidingWindow(ddos.window_seconds)
            w = self._pkt_windows[key]
            w.add(now)
            cnt = w.count()
            if cnt >= ddos.threshold:
                ratio = cnt / ddos.threshold
                conf = compute_confidence("ddos", ratio)
                sev = compute_severity(ddos.attack_type, packet.dst_port, conf)
                alerts.append(Alert(
                    severity=sev, attack_type=ddos.attack_type,
                    src_ip=packet.src_ip, dst_ip=packet.dst_ip,
                    protocol=packet.protocol, port=packet.dst_port,
                    confidence_score=conf, rule_triggered="ddos",
                    packet_count=cnt,
                ))

        # ── Port Scan rule ──
        ps = RULES["port_scan"]
        if isinstance(ps, ThresholdRule):
            self._port_sets[packet.src_ip].add(packet.dst_port)
            if packet.src_ip not in self._port_windows:
                self._port_windows[packet.src_ip] = _SlidingWindow(ps.window_seconds)
            self._port_windows[packet.src_ip].add(now)
            unique = len(self._port_sets[packet.src_ip])
            if unique >= ps.threshold:
                ratio = unique / ps.threshold
                conf = compute_confidence("port_scan", ratio)
                sev = compute_severity(ps.attack_type, packet.dst_port, conf)
                alerts.append(Alert(
                    severity=sev, attack_type=ps.attack_type,
                    src_ip=packet.src_ip, dst_ip=packet.dst_ip,
                    protocol=packet.protocol, port=packet.dst_port,
                    confidence_score=conf, rule_triggered="port_scan",
                    packet_count=unique,
                ))
                self._port_sets[packet.src_ip].clear()

        # ── Brute Force rule ──
        bf = RULES["brute_force"]
        if isinstance(bf, ThresholdRule) and "SYN" in packet.flags:
            p = packet.dst_port
            if p not in self._syn_windows:
                self._syn_windows[p] = _SlidingWindow(bf.window_seconds)
            self._syn_windows[p].add(now)
            cnt = self._syn_windows[p].count()
            if cnt >= bf.threshold:
                ratio = cnt / bf.threshold
                conf = compute_confidence("brute_force", ratio)
                sev = compute_severity(bf.attack_type, p, conf)
                alerts.append(Alert(
                    severity=sev, attack_type=bf.attack_type,
                    src_ip=packet.src_ip, dst_ip=packet.dst_ip,
                    protocol=packet.protocol, port=p,
                    confidence_score=conf, rule_triggered="brute_force",
                    packet_count=cnt,
                ))

        # ── Data Exfiltration rule ──
        exfil = RULES["data_exfil"]
        if isinstance(exfil, CompositeRule):
            if (packet.payload_entropy > 7.0
                    and packet.size_bytes > 40000
                    and packet.dst_port not in COMMON_PORTS):
                conf = 0.85
                sev = compute_severity(exfil.attack_type, packet.dst_port, conf)
                alerts.append(Alert(
                    severity=sev, attack_type=exfil.attack_type,
                    src_ip=packet.src_ip, dst_ip=packet.dst_ip,
                    protocol=packet.protocol, port=packet.dst_port,
                    confidence_score=conf, rule_triggered="data_exfil",
                    packet_count=1,
                ))

        return alerts


# Singleton
detector = Detector()
