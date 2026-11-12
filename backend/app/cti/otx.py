"""AlienVault OTX (LevelBlue) adapter — indicator "general" section lookups.

API: GET https://otx.alienvault.com/api/v1/indicators/{type}/{indicator}/general
Header: X-OTX-API-KEY (free account key).
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from app.cti.base import CTIProvider, ProviderError, freshness

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
TYPE_MAP = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url", "md5": "file", "sha1": "file",
            "sha256": "file", "cve": "cve"}


class OTX(CTIProvider):
    key = "otx"
    name = "AlienVault OTX"
    homepage = "https://otx.alienvault.com"
    supports = set(TYPE_MAP)
    credential_names = ("otx_api_key",)

    def config_hint(self) -> str:
        return "Set OTX_API_KEY (free account at https://otx.alienvault.com/)."

    async def fetch_raw(self, client: httpx.AsyncClient, itype: str, value: str) -> tuple[Any, int]:
        url = f"{OTX_BASE}/{TYPE_MAP[itype]}/{quote(value, safe='')}/general"
        resp = await client.get(url, headers={"X-OTX-API-KEY": self.credentials["otx_api_key"]})
        if resp.status_code == 404:
            return {"pulse_info": {"count": 0, "pulses": []}, "_http_404": True}, 404
        self.check_http(resp)
        return resp.json(), resp.status_code

    def parse(self, itype: str, value: str, raw: Any) -> dict:
        if not isinstance(raw, dict):
            raise ProviderError("error", "Unexpected OTX response")
        pi = raw.get("pulse_info") or {}
        pulses = pi.get("pulses") or []
        count = int(pi.get("count") or len(pulses))
        validation = [v for v in raw.get("validation") or [] if isinstance(v, dict)]
        malware = sorted({m.get("display_name") for p in pulses for m in p.get("malware_families") or []
                          if isinstance(m, dict) and m.get("display_name")})
        actors = sorted({p.get("adversary") for p in pulses if p.get("adversary")})
        attack = sorted({a.get("id") for p in pulses for a in p.get("attack_ids") or [] if isinstance(a, dict) and a.get("id")})
        tags = sorted({t for p in pulses for t in p.get("tags") or [] if t})[:25]
        refs = [f"https://otx.alienvault.com/pulse/{p['id']}" for p in pulses[:5] if p.get("id")]
        refs += [r for r in (pi.get("references") or [])[:5] if isinstance(r, str)]
        last = max((p.get("modified") or p.get("created") or "" for p in pulses), default=None) or None
        first = min((p.get("created") or "" for p in pulses), default=None) or None
        if count == 0 and validation:
            return {"status": "ok", "verdict": "allowlisted", "tags": [v.get("source", "") for v in validation],
                    "summary": "No pulses; indicator is on OTX validation lists: "
                               + ", ".join(v.get("name") or v.get("source", "") for v in validation)}
        if count == 0:
            return {"status": "no_results", "verdict": "not_found", "summary": "No OTX pulses reference this indicator"}
        verdict = "unknown" if validation else ("malicious" if count >= 3 else "suspicious")
        return {
            "status": "ok", "verdict": verdict, "malware": malware, "threat_actors": actors, "mitre": attack,
            "tags": tags, "references": refs, "confidence": min(95, 30 + 10 * count),
            "first_seen": first, "last_seen": last, "freshness_days": freshness(last),
            "threat_type": "community_pulses",
            "summary": f"Referenced in {count} OTX pulse(s)" + (" — but also on validation lists" if validation else ""),
        }
