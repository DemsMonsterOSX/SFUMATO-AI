"""Common types for CTI provider adapters.

Every adapter is split into `fetch_raw` (network I/O against the real API) and `parse` (pure
normalisation of the provider's response). Demo mode feeds recorded, clearly labelled fixture
responses through the *same* `parse` function, so both modes exercise the same code path.
"""
from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

Verdict = Literal["malicious", "suspicious", "allowlisted", "unknown", "not_found"]
Status = Literal["ok", "no_results", "error", "timeout", "rate_limited", "not_configured", "unauthorized"]


class ProviderResult(BaseModel):
    provider: str
    provider_name: str
    indicator: str
    indicator_type: str
    data_origin: Literal["live", "demo_fixture", "cache"]
    status: Status
    verdict: Verdict = "not_found"
    threat_type: str | None = None
    malware: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    confidence: int | None = None
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    relationships: list[dict] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    freshness_days: float | None = None
    duration_ms: int | None = None
    http_status: int | None = None
    error: str | None = None
    summary: str | None = None
    raw: Any = None
    queried_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ProviderError(Exception):
    def __init__(self, status: Status, message: str, http_status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.http_status = http_status
        self.retryable = retryable


def freshness(last_seen: str | None) -> float | None:
    if not last_seen:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(last_seen.replace("Z", "").split("+")[0], fmt).replace(tzinfo=timezone.utc)
            return round((datetime.now(timezone.utc) - dt).total_seconds() / 86400, 1)
        except ValueError:
            continue
    return None


class CTIProvider(ABC):
    key: str
    name: str
    homepage: str
    supports: set[str]
    #: self-hosted providers (OpenCTI) may receive internal indicators; public ones never do
    local: bool = False
    requires_credentials: bool = True
    credential_names: tuple[str, ...] = ()

    def __init__(self, credentials: dict[str, str | None]):
        self.credentials = credentials

    def configured(self) -> bool:
        return all(self.credentials.get(n) for n in self.credential_names)

    def config_hint(self) -> str:
        return ""

    @abstractmethod
    async def fetch_raw(self, client: httpx.AsyncClient, itype: str, value: str) -> tuple[Any, int]:
        """Return (raw JSON response, HTTP status). Raise ProviderError on failure."""

    @abstractmethod
    def parse(self, itype: str, value: str, raw: Any) -> dict:
        """Map a raw provider response to ProviderResult fields (status, verdict, …)."""

    def lookup_key(self, itype: str, value: str) -> str:
        return f"{itype}:{value}"

    @staticmethod
    def check_http(resp: httpx.Response) -> None:
        if resp.status_code in (401, 403):
            raise ProviderError("unauthorized", f"HTTP {resp.status_code}: credentials rejected", resp.status_code)
        if resp.status_code == 429:
            raise ProviderError("rate_limited", "HTTP 429: provider rate limit reached", 429, retryable=True)
        if resp.status_code >= 500:
            raise ProviderError("error", f"HTTP {resp.status_code} from provider", resp.status_code, retryable=True)
        if resp.status_code >= 400:
            raise ProviderError("error", f"HTTP {resp.status_code}: {resp.text[:200]}", resp.status_code)


async def with_retries(coro_factory, retries: int, base_delay: float = 0.6):
    attempt = 0
    while True:
        try:
            return await coro_factory()
        except ProviderError as e:
            if not e.retryable or attempt >= retries:
                raise
        except (httpx.TimeoutException, asyncio.TimeoutError):
            if attempt >= retries:
                raise ProviderError("timeout", "Provider did not answer before the timeout", retryable=True)
        except httpx.TransportError as e:
            if attempt >= retries:
                raise ProviderError("error", f"Network error: {type(e).__name__}: {e}", retryable=True)
        attempt += 1
        await asyncio.sleep(base_delay * (2 ** (attempt - 1)))


def timer() -> callable:
    start = time.perf_counter()
    return lambda: int((time.perf_counter() - start) * 1000)
