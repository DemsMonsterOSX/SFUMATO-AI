"""CTI enrichment engine.

Modes
-----
* live — real HTTP calls to every configured provider (with timeouts, retries, Redis cache).
* demo — recorded provider responses from examples/fixtures/cti/*.json, explicitly labelled
  `demo_fixture`, passed through the same parsers as live responses.

Privacy rules (both modes)
--------------------------
* Indicators that are private, loopback, link-local, internal or personal (e-mail) are never sent to
  public providers. Only self-hosted OpenCTI may receive them.
* RFC 5737 / RFC 2606 documentation values are not routable, so they are never queried live. The demo
  dataset deliberately uses those ranges so no real infrastructure is ever labelled malicious; in demo
  mode they are looked up in the local fixtures only.
"""
from __future__ import annotations

import asyncio
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Awaitable, Callable

import httpx

from app.core.cache import cache
from app.core.config import get_settings
from app.cti.abusech import ThreatFox, URLhaus
from app.cti.base import CTIProvider, ProviderError, ProviderResult, timer, with_retries
from app.cti.cisa_kev import CisaKEV
from app.cti.opencti import OpenCTI
from app.cti.otx import OTX
from app.schemas.evidence import ExtractedIndicator
from app.services.credentials import get_credentials

log = logging.getLogger("sfumato.cti")

PROVIDER_CLASSES: list[type[CTIProvider]] = [OpenCTI, ThreatFox, URLhaus, OTX, CisaKEV]

NOT_FOUND_FIXTURE = {
    "threatfox": {"query_status": "no_result", "data": "Your search did not yield any results"},
    "urlhaus": {"query_status": "no_results"},
    "otx": {"pulse_info": {"count": 0, "pulses": []}, "validation": []},
    "cisa_kev": {"catalogVersion": "demo-fixture", "match": None},
    "opencti": {"data": {"stixCyberObservables": {"edges": []}, "indicators": {"edges": []}}},
}


@lru_cache
def load_fixtures() -> dict[str, dict]:
    base = Path(get_settings().examples_dir) / "fixtures" / "cti"
    out: dict[str, dict] = {}
    for p in base.glob("*.json"):
        with p.open("r", encoding="utf-8") as fh:
            out[p.stem] = json.load(fh).get("entries", {})
    return out


def build_providers() -> list[CTIProvider]:
    creds = get_credentials()
    return [cls(creds) for cls in PROVIDER_CLASSES]


def provider_catalog(mode: str | None = None) -> list[dict]:
    mode = mode or get_settings().cti_mode
    rows = []
    for p in build_providers():
        rows.append({
            "key": p.key, "name": p.name, "homepage": p.homepage, "supports": sorted(p.supports),
            "self_hosted": p.local, "requires_credentials": p.requires_credentials,
            "configured": p.configured(), "hint": p.config_hint() if not p.configured() else None,
            "available_in_demo": True,
        })
    return rows


def _eligible(ind: ExtractedIndicator, provider: CTIProvider, mode: str) -> tuple[bool, str | None]:
    if ind.type not in provider.supports:
        return False, None
    if ind.shareable:
        return True, None
    if ind.scope == "documentation":
        if mode == "demo":
            return True, None
        return False, "documentation/reserved value — not routable, never sent to live providers"
    if provider.local and ind.scope in ("private", "internal", "loopback", "link_local", "unknown"):
        return True, None
    return False, f"{ind.scope} indicator — not sent to public third-party providers"


async def _query_one(client: httpx.AsyncClient, provider: CTIProvider, ind: ExtractedIndicator, mode: str) -> ProviderResult:
    settings = get_settings()
    elapsed = timer()
    base = {"provider": provider.key, "provider_name": provider.name, "indicator": ind.value,
            "indicator_type": ind.type}
    if mode == "demo":
        raw = load_fixtures().get(provider.key, {}).get(provider.lookup_key(ind.type, ind.value))
        raw = raw if raw is not None else NOT_FOUND_FIXTURE[provider.key]
        try:
            parsed = provider.parse(ind.type, ind.value, raw)
            return ProviderResult(**base, data_origin="demo_fixture", raw=raw, duration_ms=elapsed(), **parsed)
        except ProviderError as e:
            return ProviderResult(**base, data_origin="demo_fixture", status=e.status, verdict="unknown",
                                  error=str(e), raw=raw, duration_ms=elapsed())

    cache_key = f"cti:{provider.key}:{ind.type}:{ind.value}"
    cached = cache.get(cache_key)
    if cached:
        res = ProviderResult.model_validate(cached)
        res.data_origin = "cache"
        res.duration_ms = elapsed()
        return res
    try:
        raw, http_status = await with_retries(
            lambda: asyncio.wait_for(provider.fetch_raw(client, ind.type, ind.value), settings.cti_timeout_seconds),
            retries=settings.cti_max_retries)
        parsed = provider.parse(ind.type, ind.value, raw)
        res = ProviderResult(**base, data_origin="live", raw=raw, http_status=http_status, duration_ms=elapsed(),
                             **parsed)
        cache.set(cache_key, res.model_dump(mode="json"), settings.cti_cache_ttl_seconds)
        return res
    except ProviderError as e:
        return ProviderResult(**base, data_origin="live", status=e.status, verdict="unknown", error=str(e),
                              http_status=e.http_status, duration_ms=elapsed())
    except Exception as e:  # never let one provider break the investigation
        log.exception("Unexpected error querying %s", provider.key)
        return ProviderResult(**base, data_origin="live", status="error", verdict="unknown",
                              error=f"{type(e).__name__}: {e}", duration_ms=elapsed())


async def enrich(indicators: list[ExtractedIndicator], mode: str,
                 on_result: Callable[[ProviderResult], Awaitable[None]] | None = None) -> dict:
    settings = get_settings()
    providers = build_providers()
    plan: list[tuple[CTIProvider, ExtractedIndicator]] = []
    skipped: list[dict] = []
    provider_state: dict[str, dict] = {
        p.key: {"key": p.key, "name": p.name, "configured": p.configured() or mode == "demo", "queries": 0,
                "ok": 0, "errors": 0, "hint": None if (p.configured() or mode == "demo") else p.config_hint()}
        for p in providers}

    for ind in indicators:
        for p in providers:
            ok, reason = _eligible(ind, p, mode)
            if not ok:
                if reason and ind.type in p.supports:
                    skipped.append({"indicator": ind.value, "type": ind.type, "provider": p.key, "reason": reason})
                continue
            if mode == "live" and not p.configured():
                continue
            plan.append((p, ind))

    sem = asyncio.Semaphore(6)
    results: list[ProviderResult] = []

    async def run(p: CTIProvider, ind: ExtractedIndicator, client: httpx.AsyncClient):
        async with sem:
            r = await _query_one(client, p, ind, mode)
        st = provider_state[p.key]
        st["queries"] += 1
        st["ok" if r.status in ("ok", "no_results") else "errors"] += 1
        results.append(r)
        if on_result:
            await on_result(r)

    async with httpx.AsyncClient(timeout=settings.cti_timeout_seconds,
                                 headers={"User-Agent": "Sfumato-Autonomous-SOC/1.0 (read-only CTI lookups)"}) as client:
        await asyncio.gather(*(run(p, i, client) for p, i in plan))

    order = {(p.key, i.value): n for n, (p, i) in enumerate(plan)}
    results.sort(key=lambda r: order.get((r.provider, r.indicator), 0))
    answered = sum(1 for r in results if r.status in ("ok", "no_results"))
    return {
        "mode": mode,
        "results": results,
        "skipped": skipped,
        "providers": list(provider_state.values()),
        "planned_queries": len(plan),
        "coverage": round(answered / len(plan), 3) if plan else 0.0,
    }
