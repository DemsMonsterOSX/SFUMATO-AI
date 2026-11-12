"""abuse.ch ThreatFox and URLhaus adapters (read-only lookups).

Both APIs require a free `Auth-Key` from https://auth.abuse.ch/ sent as an HTTP header.
API references: https://threatfox.abuse.ch/api/ and https://urlhaus-api.abuse.ch/
"""
from __future__ import annotations

from typing import Any

import httpx

from app.cti.base import CTIProvider, ProviderError, freshness

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"


class ThreatFox(CTIProvider):
    key = "threatfox"
    name = "ThreatFox (abuse.ch)"
    homepage = "https://threatfox.abuse.ch"
    supports = {"ipv4", "domain", "url", "md5", "sha256"}
    credential_names = ("abusech_auth_key",)

    def config_hint(self) -> str:
        return "Set ABUSECH_AUTH_KEY (free key from https://auth.abuse.ch/)."

    async def fetch_raw(self, client: httpx.AsyncClient, itype: str, value: str) -> tuple[Any, int]:
        if itype in ("md5", "sha256"):
            body = {"query": "search_hash", "hash": value}
        else:
            body = {"query": "search_ioc", "search_term": value, "exact_match": True}
        resp = await client.post(THREATFOX_URL, json=body, headers={"Auth-Key": self.credentials["abusech_auth_key"]})
        self.check_http(resp)
        return resp.json(), resp.status_code

    def parse(self, itype: str, value: str, raw: Any) -> dict:
        status = (raw or {}).get("query_status")
        if status in ("no_result", "no_results"):
            return {"status": "no_results", "verdict": "not_found", "summary": "IOC not present in ThreatFox"}
        if status != "ok":
            raise ProviderError("error", f"ThreatFox query_status={status!r}: {(raw or {}).get('data')}")
        rows = [r for r in raw.get("data") or [] if isinstance(r, dict)]
        if itype in ("ipv4",):  # ThreatFox stores ip:port IOCs; keep exact host matches only
            rows = [r for r in rows if str(r.get("ioc", "")).split(":")[0] == value] or rows
        if not rows:
            return {"status": "no_results", "verdict": "not_found", "summary": "IOC not present in ThreatFox"}
        malware = sorted({r.get("malware_printable") for r in rows if r.get("malware_printable")})
        tags = sorted({t for r in rows for t in (r.get("tags") or []) if t})
        refs = sorted({r["reference"] for r in rows if r.get("reference")})
        refs += [f"https://threatfox.abuse.ch/ioc/{r['id']}/" for r in rows[:5] if r.get("id")]
        conf = max((int(r.get("confidence_level") or 0) for r in rows), default=None)
        last = max((r.get("last_seen") or r.get("first_seen") or "" for r in rows), default=None) or None
        first = min((r.get("first_seen") or "" for r in rows), default=None) or None
        return {
            "status": "ok", "verdict": "malicious",
            "threat_type": rows[0].get("threat_type_desc") or rows[0].get("threat_type"),
            "malware": malware, "tags": tags, "references": refs, "confidence": conf,
            "first_seen": first, "last_seen": last, "freshness_days": freshness(last),
            "summary": f"{len(rows)} ThreatFox IOC record(s): {', '.join(malware) or 'unattributed'}",
        }


class URLhaus(CTIProvider):
    key = "urlhaus"
    name = "URLhaus (abuse.ch)"
    homepage = "https://urlhaus.abuse.ch"
    supports = {"ipv4", "domain", "url", "md5", "sha256"}
    credential_names = ("abusech_auth_key",)

    def config_hint(self) -> str:
        return "Set ABUSECH_AUTH_KEY (free key from https://auth.abuse.ch/)."

    async def fetch_raw(self, client: httpx.AsyncClient, itype: str, value: str) -> tuple[Any, int]:
        if itype == "url":
            path, data = "url/", {"url": value}
        elif itype in ("md5", "sha256"):
            path, data = "payload/", {f"{itype}_hash": value}
        else:
            path, data = "host/", {"host": value}
        resp = await client.post(URLHAUS_URL + path, data=data, headers={"Auth-Key": self.credentials["abusech_auth_key"]})
        self.check_http(resp)
        return resp.json(), resp.status_code

    def parse(self, itype: str, value: str, raw: Any) -> dict:
        raw = raw or {}
        status = raw.get("query_status") or raw.get("query_staus")
        if status == "no_results":
            return {"status": "no_results", "verdict": "not_found", "summary": "Not present in URLhaus"}
        if status != "ok":
            raise ProviderError("error", f"URLhaus query_status={status!r}")
        blacklists = {k: v for k, v in (raw.get("blacklists") or {}).items() if v and v != "not listed"}
        tags: set[str] = set()
        refs = [raw["urlhaus_reference"]] if raw.get("urlhaus_reference") else []
        if itype == "url":
            online = raw.get("url_status") == "online"
            tags.update(raw.get("tags") or [])
            malware = sorted({p.get("signature") for p in raw.get("payloads") or [] if p.get("signature")})
            return {
                "status": "ok", "verdict": "malicious", "threat_type": raw.get("threat") or "malware_download",
                "malware": malware, "tags": sorted(tags), "references": refs, "confidence": 90 if online else 75,
                "first_seen": raw.get("date_added"), "last_seen": raw.get("last_online") or raw.get("date_added"),
                "freshness_days": freshness(raw.get("last_online") or raw.get("date_added")),
                "summary": f"URL listed by URLhaus (status: {raw.get('url_status')})",
            }
        if itype in ("md5", "sha256"):
            sig = raw.get("signature")
            return {
                "status": "ok", "verdict": "malicious", "threat_type": "malware_payload",
                "malware": [sig] if sig else [], "references": refs, "confidence": 85,
                "first_seen": raw.get("firstseen"), "last_seen": raw.get("lastseen"),
                "freshness_days": freshness(raw.get("lastseen")),
                "summary": f"Payload known to URLhaus ({raw.get('file_type')}, {raw.get('url_count')} URL(s))",
            }
        urls = raw.get("urls") or []
        online = [u for u in urls if u.get("url_status") == "online"]
        for u in urls:
            tags.update(u.get("tags") or [])
        last = max((u.get("date_added") or "" for u in urls), default=None) or raw.get("firstseen")
        verdict = "malicious" if online or blacklists else "suspicious"
        return {
            "status": "ok", "verdict": verdict, "threat_type": "malware_distribution_host",
            "tags": sorted(tags) + [f"{k}:{v}" for k, v in blacklists.items()], "references": refs,
            "confidence": 85 if online else 55, "first_seen": raw.get("firstseen"), "last_seen": last,
            "freshness_days": freshness(last),
            "summary": f"Host served {raw.get('url_count', len(urls))} malicious URL(s), {len(online)} currently online",
        }
