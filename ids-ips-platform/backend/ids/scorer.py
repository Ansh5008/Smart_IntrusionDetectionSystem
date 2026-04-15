"""Severity scoring algorithm."""
from __future__ import annotations
from ids.rules import COMMON_PORTS


HIGH_RISK_PORTS = {22, 23, 3389, 445, 3306, 1433, 5432}


def compute_severity(attack_type: str, port: int, confidence: float) -> str:
    if confidence >= 0.9 and port in HIGH_RISK_PORTS:
        return "Critical"
    if confidence >= 0.8 or attack_type in ("DDoS Flood", "Data Exfiltration"):
        return "High" if port not in HIGH_RISK_PORTS else "Critical"
    if confidence >= 0.6:
        return "Medium"
    return "Low"


def compute_confidence(rule_name: str, ratio: float) -> float:
    """ratio = actual_value / threshold. Higher means more confident."""
    base = min(ratio, 3.0) / 3.0  # normalize to 0-1
    return round(0.5 + base * 0.5, 3)  # range 0.5 – 1.0
