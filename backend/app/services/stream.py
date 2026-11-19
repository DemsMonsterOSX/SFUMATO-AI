"""Streaming status: measured results (ml/stream/results.json) and the live state published by the streaming applications.

The producer, scorers and CVE consumers write small JSON documents to gs://BUCKET/stream/state/. On the VM this service reads them
with the VM's own identity (metadata server token, read-only). Elsewhere (local development) only the measured results exist.
A component is "active" when its document was refreshed within the last 30 seconds.
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse
from pathlib import Path

import httpx

from app.core.config import get_settings

_cache: dict = {"at": 0.0, "value": None}
_MD = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"


def _bucket() -> str | None:
    m = re.match(r"^gs://([^/]+)", get_settings().ml_artifact_uri or "")
    return m.group(1) if m else None


def results() -> dict | None:
    p = Path(get_settings().repo_dir) / "ml" / "stream" / "results.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, ValueError):
        return None


def live() -> dict:
    """Documents under stream/state/, keyed by name. Empty when the bucket is not reachable."""
    if _cache["value"] is not None and time.time() - _cache["at"] < 4:
        return _cache["value"]
    out: dict = {}
    b = _bucket()
    if b:
        try:
            with httpx.Client(timeout=5.0) as c:
                t = c.get(_MD, headers={"Metadata-Flavor": "Google"})
                if t.status_code == 200:
                    h = {"Authorization": "Bearer " + t.json()["access_token"]}
                    lst = c.get(f"https://storage.googleapis.com/storage/v1/b/{b}/o", params={"prefix": "stream/state/"}, headers=h)
                    for item in (lst.json().get("items", []) if lst.status_code == 200 else []):
                        r = c.get(f"https://storage.googleapis.com/storage/v1/b/{b}/o/{urllib.parse.quote(item['name'], safe='')}?alt=media", headers=h)
                        if r.status_code == 200:
                            out[item["name"].split("/")[-1].removesuffix(".json")] = r.json()
        except Exception:
            out = {}
    _cache.update(at=time.time(), value=out)
    return out


def overview() -> dict:
    docs = live()
    now = time.time()
    scorers = sorted([v for k, v in docs.items() if k.startswith("scorer-")], key=lambda v: v["host"])
    producers = sorted([v for k, v in docs.items() if k.startswith("producer-")], key=lambda v: v["host"])
    for v in scorers + producers:
        v["age_s"] = round(now - v.get("updated_at", 0))
        v["active"] = v["age_s"] < 30
    cve_c, cve_b = docs.get("cve-consumer"), docs.get("cve-bridge")
    active = any(v["active"] for v in scorers + producers)
    cm = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    per_label: dict[str, dict] = {}
    for s in scorers:
        for k in cm:
            cm[k] += int(s.get("confusion", {}).get(k, 0))
        for lab, v in s.get("per_label", {}).items():
            d = per_label.setdefault(lab, {"flows": 0, "flagged": 0})
            d["flows"] += v["flows"]
            d["flagged"] += v["flagged"]
    tp, fp, fn = cm["tp"], cm["fp"], cm["fn"]
    return {"active": active, "live_available": bool(docs), "scorers": scorers, "producers": producers, "cve_consumer": cve_c, "cve_bridge": cve_b,
            "totals": {"confusion": cm, "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / (tp + fn) if tp + fn else None,
                       "consumed": sum(s.get("consumed", 0) for s in scorers), "throughput_per_s": round(sum(s["throughput_per_s"] for s in scorers if s["active"]), 1),
                       "per_label": per_label},
            "results": results()}
