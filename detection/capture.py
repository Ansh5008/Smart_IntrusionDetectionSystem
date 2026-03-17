from __future__ import annotations

from typing import Any

from alerts.alert import send_alert
from detection.predict import load_artifacts, predict


def extract_features(packet: Any, feature_columns: list[str]) -> dict[str, float]:
    values: dict[str, float] = {col: 0.0 for col in feature_columns}

    length = float(len(packet))
    if "Packet Length Mean" in values:
        values["Packet Length Mean"] = length
    if "Packet Length Max" in values:
        values["Packet Length Max"] = length
    if "Total Length of Fwd Packets" in values:
        values["Total Length of Fwd Packets"] = length

    has_tcp = float(int(packet.haslayer("TCP")))
    has_udp = float(int(packet.haslayer("UDP")))
    if "Protocol" in values:
        values["Protocol"] = 6.0 if has_tcp else 17.0 if has_udp else 0.0

    return values


def process_packet(packet: Any, artifacts: dict[str, Any]) -> None:
    try:
        feature_columns = artifacts["feature_columns"]
        features = extract_features(packet, feature_columns)
        result = predict(features, artifacts=artifacts)

        print("Prediction:", result)
        if result == "ATTACK":
            send_alert("Intrusion Detected!")
    except Exception as exc:
        print("Error:", exc)


def start_capture() -> None:
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("scapy is not installed. Install dependencies first.") from exc

    artifacts = load_artifacts()
    print("Starting packet capture...")
    sniff(prn=lambda pkt: process_packet(pkt, artifacts), store=False)