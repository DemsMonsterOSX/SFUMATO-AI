"""Response-procedure library (about 100 draft runbooks, NIST SP 800-61 phases, MITRE ATT&CK ids)."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.config import get_settings
from app.core.ttlcache import ttl_cache
from app.core.security import require_api_key
from app.services import procedures as lib

router = APIRouter(prefix="/api/v1/procedures", tags=["procedures"], dependencies=[Depends(require_api_key)])


def _manifest() -> dict | None:
    p = Path(get_settings().repo_dir) / "ml" / "procedures" / "manifest.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, ValueError):
        return None


@router.get("", summary="List or search procedures (q = free text, filters by tactic and severity)")
@ttl_cache(60)
def list_procedures(q: str | None = Query(None, max_length=200), tactic: str | None = None, severity: str | None = None,
                    limit: int = Query(200, ge=1, le=200)):
    if not lib.available():
        return {"available": False, "count": 0, "items": [], "tactics": [], "manifest": None}
    items = lib.search(q, limit, tactic, severity) if q and q.strip() else [
        i for i in lib.list_all() if (not tactic or i["tactic"].lower() == tactic.lower())
        and (not severity or i["severity"].lower() == severity.lower())][:limit]
    everything = lib.list_all()
    return {"available": True, "count": len(items), "total": len(everything), "items": items,
            "tactics": sorted({i["tactic"] for i in everything}), "manifest": _manifest()}


@router.get("/{pid}", summary="One procedure with all its sections")
def get_procedure(pid: str):
    p = lib.get(pid)
    if not p:
        raise HTTPException(404, "Unknown procedure")
    return p
