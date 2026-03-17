from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class Alert:
    row_id: int
    label: str
    score: float
    timestamp: str


def _is_malicious(label: str) -> bool:
    normalized = str(label).strip().lower()
    if normalized in {"benign", "normal", "0"}:
        return False
    return True


def emit_alerts(
    predictions: Iterable[dict],
    out_path: Optional[Path] = None,
    min_score: float = 0.5,
) -> list[Alert]:
    alerts: list[Alert] = []
    for pred in predictions:
        label = pred.get("label", "unknown")
        score = float(pred.get("score", 0.0))
        row_id = int(pred.get("row_id", -1))
        if not _is_malicious(label):
            continue
        if score < min_score:
            continue
        alerts.append(
            Alert(
                row_id=row_id,
                label=str(label),
                score=score,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(json.dumps(asdict(alert)) + "\n")

    return alerts


def send_alert(message: str) -> None:
    """Simple alert dispatcher — prints to console."""
    print(f"[ALERT] {datetime.now(timezone.utc).isoformat()} — {message}")
