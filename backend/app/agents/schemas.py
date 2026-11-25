"""Structured output contract for the AI investigator (validated with Pydantic)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

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

    @field_validator("confidence_limitations", mode="before")
    @classmethod
    def _limitations_as_text(cls, v):
        """Some models answer with the same {"statement": ...} objects they use for claims; keep their text instead of rejecting the whole report."""
        if not isinstance(v, list):
            return v
        out = []
        for x in v:
            if isinstance(x, dict):
                text = next((str(x[k]) for k in ("statement", "text", "limitation", "description") if x.get(k)), None)
                x = text if text is not None else "; ".join(f"{k}: {val}" for k, val in x.items())
            out.append(x if isinstance(x, str) else str(x))
        return out


class AgentReport(AgentOutput):
    """AgentOutput after server-side validation, plus provenance."""
    provider: str
    model: str
    mode: Literal["llm", "deterministic"]
    latency_ms: int
    fallback_reason: str | None = None
    redaction_applied: bool = False
    validation: dict = Field(default_factory=dict)
