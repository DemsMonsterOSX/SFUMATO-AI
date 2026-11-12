"""CISA Known Exploited Vulnerabilities catalogue (public JSON feed, no key required)."""
from __future__ import annotations

import time
from typing import Any

import httpx

from app.core.config import get_settings
from app.cti.base import CTIProvider, freshness

_CATALOG: dict[str, Any] = {"loaded_at": 0.0, "data": None}
CATALOG_TTL = 12 * 3600


class CisaKEV(CTIProvider):
    key = "cisa_kev"
    name = "CISA KEV"
    homepage = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    supports = {"cve"}
    requires_credentials = False

    def configured(self) -> bool:
        return True

    async def _catalog(self, client: httpx.AsyncClient) -> dict:
        if _CATALOG["data"] is None or time.time() - _CATALOG["loaded_at"] > CATALOG_TTL:
            resp = await client.get(get_settings().cisa_kev_url, timeout=30)
            self.check_http(resp)
            _CATALOG["data"] = resp.json()
            _CATALOG["loaded_at"] = time.time()
        return _CATALOG["data"]

    async def fetch_raw(self, client: httpx.AsyncClient, itype: str, value: str) -> tuple[Any, int]:
        cat = await self._catalog(client)
        match = next((v for v in cat.get("vulnerabilities", []) if v.get("cveID", "").upper() == value.upper()), None)
        return {"catalogVersion": cat.get("catalogVersion"), "dateReleased": cat.get("dateReleased"),
                "count": cat.get("count"), "match": match}, 200

    def parse(self, itype: str, value: str, raw: Any) -> dict:
        m = (raw or {}).get("match")
        if not m:
            return {"status": "no_results", "verdict": "not_found",
                    "summary": f"Not in CISA KEV (catalogue {raw.get('catalogVersion')})"}
        ransomware = (m.get("knownRansomwareCampaignUse") or "").lower() == "known"
        return {
            "status": "ok", "verdict": "malicious", "threat_type": "known_exploited_vulnerability",
            "tags": [m.get("vendorProject", ""), m.get("product", "")] + (["ransomware-campaign-use"] if ransomware else []),
            "references": [f"https://nvd.nist.gov/vuln/detail/{value}", self.homepage],
            "confidence": 100, "first_seen": m.get("dateAdded"), "last_seen": m.get("dateAdded"),
            "freshness_days": freshness(m.get("dateAdded")),
            "summary": f"{m.get('vulnerabilityName')} — actively exploited (added {m.get('dateAdded')})",
        }
