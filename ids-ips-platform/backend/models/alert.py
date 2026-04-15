"""Alert Pydantic models."""
from __future__ import annotations
from datetime import datetime
from uuid import UUID, uuid4
from typing import Literal, Optional
from pydantic import BaseModel, Field


class Alert(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: Literal["Low", "Medium", "High", "Critical"]
    attack_type: str
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    confidence_score: float = 0.0
    rule_triggered: str = ""
    packet_count: int = 1
    status: Literal["open", "acknowledged", "resolved"] = "open"
    assigned_to: Optional[str] = None


class AlertUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"] | None = None
    assigned_to: str | None = None
