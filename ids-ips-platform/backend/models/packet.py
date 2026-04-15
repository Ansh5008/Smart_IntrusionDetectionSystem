"""Packet Pydantic models."""
from __future__ import annotations
from datetime import datetime
from uuid import UUID, uuid4
from typing import Literal
from pydantic import BaseModel, Field


class Packet(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Literal["TCP", "UDP", "ICMP"]
    size_bytes: int
    ttl: int = 64
    flags: list[str] = Field(default_factory=list)
    payload_entropy: float = 0.0
    geo_country: str = "US"
    is_flagged: bool = False
