"""Vulnerability feed summary (CISA KEV + NVD + EPSS) published by bigdata/cve_ingest.py.

Source order: the bucket copy (gs://BUCKET/cve/latest/summary.json, read with the VM's own identity through the metadata server,
so a new ingestion shows up without redeploying) then the copy shipped with the application (ml/cve/summary.json).
This is reference data, never evidence about an incident.
"""
from __future__ import annotations

import json
import re
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
