"""Structured output contract for the AI investigator (validated with Pydantic)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

VerdictName = Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "LEGITIMATE_ACTIVITY", "INCONCLUSIVE"]


class Claim(BaseModel):
    statement: str = Field(max_length=1200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


class TechniqueClaim(BaseModel):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str | None = None
    rationale: str = Field(max_length=800)
    evidence_ids: list[str] = Field(default_factory=list)


class ActionClaim(BaseModel):
    action: str = Field(max_length=300)
    rationale: str = Field(max_length=800)
    evidence_ids: list[str] = Field(default_factory=list)


class AgentOutput(BaseModel):
    """What the model must return."""
    summary: str = Field(max_length=2000)
    technical_explanation: str = Field(max_length=5000)
    suspicious_behaviors: list[Claim] = Field(default_factory=list)
    cti_findings: list[Claim] = Field(default_factory=list)
    mitre_techniques: list[TechniqueClaim] = Field(default_factory=list)
    supporting_evidence: list[Claim] = Field(default_factory=list)
    contradictory_evidence: list[Claim] = Field(default_factory=list)
    confidence_limitations: list[str] = Field(default_factory=list)
    recommended_verdict: VerdictName
    recommended_actions: list[ActionClaim] = Field(default_factory=list)
    knowledge_guidance: list[Claim] = Field(default_factory=list)  # may only cite knowledge-base passages


class AgentReport(AgentOutput):
    """AgentOutput after server-side validation, plus provenance."""
    provider: str
    model: str
    mode: Literal["llm", "deterministic"]
    latency_ms: int
    fallback_reason: str | None = None
    redaction_applied: bool = False
    validation: dict = Field(default_factory=dict)
