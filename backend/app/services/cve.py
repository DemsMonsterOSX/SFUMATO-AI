"""Vulnerability feed summary (CISA KEV + NVD + EPSS) published by bigdata/cve_ingest.py.

Source order: the bucket copy (gs://BUCKET/cve/latest/summary.json, read with the VM's own identity through the metadata server,
so a new ingestion shows up without redeploying) then the copy shipped with the application (ml/cve/summary.json).
This is reference data, never evidence about an incident.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from pathlib import Path

import httpx

from app.core.config import get_settings

_cache: dict = {"at": 0.0, "value": None, "source": None}
_TTL = 600
_MD = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"


def _bucket() -> str | None:
    uri = get_settings().ml_artifact_uri or ""
    m = re.match(r"^gs://([^/]+)", uri)
    return m.group(1) if m else None


def _from_bucket() -> dict | None:
    b = _bucket()
    if not b:
        return None
    try:
        with httpx.Client(timeout=4.0) as c:
            t = c.get(_MD, headers={"Metadata-Flavor": "Google"})
            if t.status_code != 200:
                return None
            obj = urllib.parse.quote("cve/latest/summary.json", safe="")
            r = c.get(f"https://storage.googleapis.com/storage/v1/b/{b}/o/{obj}?alt=media",
                      headers={"Authorization": "Bearer " + t.json()["access_token"]})
            return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def _from_file() -> dict | None:
    p = Path(get_settings().repo_dir) / "ml" / "cve" / "summary.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, ValueError):
        return None


def summary() -> tuple[dict | None, str | None]:
    if _cache["value"] is not None and time.time() - _cache["at"] < _TTL:
        return _cache["value"], _cache["source"]
    data, source = _from_bucket(), "bucket"
    if data is None:
        data, source = _from_file(), "application package"
    _cache.update(at=time.time(), value=data, source=source if data else None)
    return data, source if data else None


def search(data: dict, q: str, limit: int = 25) -> list[dict]:
    """Substring search over the CVEs held in the summary (KEV recent additions, top CVSS, top EPSS)."""
    ql = q.lower().strip()
    if not ql:
        return []
    seen, out = set(), []
    for v in data["kev"]["recent"]:
        text = " ".join(str(v.get(k, "")) for k in ("id", "vendor", "product", "name", "description")).lower()
        if ql in text and v["id"] not in seen:
            seen.add(v["id"]); out.append({"id": v["id"], "title": f"{v['vendor']} {v['product']}: {v['name']}", "kev": True, "added": v["added"],
                                           "cvss": None, "epss": (v.get("epss") or {}).get("epss")})
    for c in data["nvd"]["top_cvss"] + data["epss"]["top"]:
        text = f"{c['id']} {c['description']} {' '.join(c['cwe'])}".lower()
        if ql in text and c["id"] not in seen:
            seen.add(c["id"]); out.append({"id": c["id"], "title": c["description"][:140], "kev": c["kev"], "added": (c["published"] or "")[:10],
                                           "cvss": (c["cvss"] or {}).get("score"), "epss": (c.get("epss") or {}).get("epss")})
    return out[:limit]


# ---- live lookup of one CVE (NVD + CISA KEV + FIRST EPSS) -----------------------------------------------------------------------
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_lookups: dict[str, tuple[float, dict]] = {}
_kev: dict = {"at": 0.0, "ids": {}}
_nvd_lock = threading.Lock()
_nvd_last = [0.0]


class RateLimited(Exception):
    pass


def _kev_ids(c: httpx.Client) -> dict:
    if time.time() - _kev["at"] > 3600 or not _kev["ids"]:
        try:
            data = c.get(KEV_URL, timeout=30.0).json()
            _kev.update(at=time.time(), ids={v["cveID"]: {"added": v["dateAdded"], "due": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse"),
                                                           "name": v["vulnerabilityName"]} for v in data["vulnerabilities"]})
        except Exception:
            pass
    return _kev["ids"]


def lookup(cve_id: str) -> dict | None:
    """One CVE fetched live: NVD record, KEV membership and EPSS. Cached 10 minutes; the NVD allows few calls without a key."""
    cve_id = cve_id.strip().upper()
    if not CVE_ID.match(cve_id):
        raise ValueError("expected an identifier such as CVE-2024-4577")
    hit = _lookups.get(cve_id)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    key = os.environ.get("NVD_API_KEY")
    with _nvd_lock:
        wait = (0.7 if key else 6.5) - (time.time() - _nvd_last[0])
        if wait > 0:
            raise RateLimited(f"the NVD rate limit is protected: retry in {wait:.0f} s")
        _nvd_last[0] = time.time()
    with httpx.Client(timeout=20.0, headers={"User-Agent": "sfumato-cve-lookup/1.0"}) as c:
        r = c.get(NVD, params={"cveId": cve_id}, headers={"apiKey": key} if key else {})
        if r.status_code != 200:
            raise RuntimeError(f"NVD answered HTTP {r.status_code}")
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0]["cve"]
        best = None
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in cve.get("metrics", {}).get(k, []) or []:
                d = m.get("cvssData", {})
                if "baseScore" in d:
                    best = {"version": d.get("version"), "score": d["baseScore"], "severity": d.get("baseSeverity") or m.get("baseSeverity"), "vector": d.get("vectorString")}
                    break
            if best:
                break
        epss = None
        try:
            e = c.get(EPSS, params={"cve": cve_id}).json().get("data", [])
            epss = {"epss": float(e[0]["epss"]), "percentile": float(e[0]["percentile"])} if e else None
        except Exception:
            pass
        kev = _kev_ids(c).get(cve_id)
    out = {"id": cve_id, "published": cve.get("published"), "modified": cve.get("lastModified"), "status": cve.get("vulnStatus"),
           "description": next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""), "cvss": best,
           "cwe": sorted({x["value"] for w in cve.get("weaknesses", []) for x in w.get("description", []) if x.get("value", "").startswith("CWE-")}),
           "kev": kev, "epss": epss, "references": [x["url"] for x in cve.get("references", [])[:6]],
           "sources": ["NIST NVD API 2.0", "CISA KEV", "FIRST EPSS"], "fetched_at": time.time()}
    _lookups[cve_id] = (time.time(), out)
    return out
