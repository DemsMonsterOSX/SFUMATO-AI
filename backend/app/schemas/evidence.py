"""Evidence model shared by the behavioural analyser, CTI correlation, ML, AI agent and decision engine."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Polarity = Literal["malicious", "suspicious", "benign", "neutral"]
Category = Literal["cti", "behavior", "context", "ml", "integrity", "knowledge"]
BenignClass = Literal["authorization", "misidentification"]


class Evidence(BaseModel):
    id: str
    category: Category
    polarity: Polarity
    kind: str
    title: str
    description: str
    weight: float = Field(ge=0, le=100)
    source: str
    benign_class: BenignClass | None = None
    mitre: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class ExtractedIndicator(BaseModel):
    value: str
    type: str
    scope: Literal["public", "private", "loopback", "link_local", "documentation", "reserved",
                   "multicast", "internal", "unknown"]
    shareable: bool  # may be sent to public third-party CTI services
    origins: list[str] = Field(default_factory=list)
    note: str | None = None
