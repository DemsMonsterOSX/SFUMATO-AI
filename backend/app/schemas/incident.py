"""Strict Pydantic schema for the Sfumato standard incident format.

Every block except `incident_id`, `timestamp`, `source`, `severity` and `alert` is optional,
because real alerts rarely carry process, user, network and file context at the same time.
Unknown top-level keys are rejected; `metadata` accepts additional context keys.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Short = Annotated[str, Field(max_length=256)]
Medium = Annotated[str, Field(max_length=4096)]
Long = Annotated[str, Field(max_length=16384)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Criticality(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IndicatorType(str, Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    hostname = "hostname"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    email = "email"
    cve = "cve"


class Alert(Strict):
    name: Short
    description: Medium | None = None
    category: Short | None = None


class Asset(Strict):
    hostname: Short | None = None
    ip: Short | None = None
    criticality: Criticality | None = None
    environment: Short | None = None
    os: Short | None = None
    owner: Short | None = None


class User(Strict):
    username: Short | None = None
    domain: Short | None = None
    email: Short | None = None
    department: Short | None = None
    is_admin: bool | None = None


class Process(Strict):
    name: Short | None = None
    parent: Short | None = None
    command_line: Long | None = None
    path: Medium | None = None
    pid: int | None = Field(default=None, ge=0)
    sha256: Short | None = None
    signer: Short | None = None
    signed: bool | None = None


class Network(Strict):
    source_ip: Short | None = None
    destination_ip: Short | None = None
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Short | None = None
    destination_domain: Short | None = None
    url: Medium | None = None
    direction: Short | None = None
    bytes_out: int | None = Field(default=None, ge=0)


class Authentication(Strict):
    result: Short | None = None  # success | failure
    failed_attempts: int | None = Field(default=None, ge=0)
    source_ip: Short | None = None
    source_country: Short | None = None
    usual_country: Short | None = None
    mfa: bool | None = None
    logon_type: Short | None = None


class FileInfo(Strict):
    name: Short | None = None
    path: Medium | None = None
    sha256: Short | None = None
    md5: Short | None = None
    signer: Short | None = None
    signed: bool | None = None


class Indicator(Strict):
    type: IndicatorType
    value: Annotated[str, Field(min_length=1, max_length=2048)]


class Metadata(BaseModel):
    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    detection_rule: Short | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    tags: list[Short] = Field(default_factory=list, max_length=64)
    change_ticket: Short | None = None
    maintenance_window: bool | None = None

    @model_validator(mode="after")
    def _limit_extra(self):
        extra = self.model_extra or {}
        if len(extra) > 32:
            raise ValueError("metadata accepts at most 32 additional keys")
        for k, v in extra.items():
            if not isinstance(v, (str, int, float, bool, type(None), list)):
                raise ValueError(f"metadata.{k} must be a scalar or a list of scalars")
            if isinstance(v, str) and len(v) > 4096:
                raise ValueError(f"metadata.{k} is too long")
        return self


class IncidentIn(Strict):
    incident_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9._:\-]{3,128}$")]
    timestamp: datetime
    source: Short
    severity: Severity
    alert: Alert
    asset: Asset | None = None
    user: User | None = None
    process: Process | None = None
    network: Network | None = None
    authentication: Authentication | None = None
    file: FileInfo | None = None
    indicators: list[Indicator] = Field(default_factory=list, max_length=200)
    metadata: Metadata = Field(default_factory=Metadata)

    @field_validator("timestamp")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must include a timezone (e.g. 2026-10-22T12:00:00Z)")
        return v


class IncidentAccepted(BaseModel):
    incident_id: str
    status: str
    message: str


def incident_json_schema() -> dict[str, Any]:
    return IncidentIn.model_json_schema()
