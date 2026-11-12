"""Health, platform status, dashboard statistics, scenarios and first-run settings."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.agents.providers import reset_status_cache, resolve_provider
from app.core.cache import cache
from app.core.config import get_settings
from app.core.security import audit, require_api_key
from app.cti.engine import provider_catalog
from app.database.session import get_db, get_engine
from app.ml.inference import model_service
from app.models import AuditLog, CTIQuery, Incident, PlaybookRun
from app.schemas.incident import incident_json_schema
from app.services import credentials
from app.soar.tasks import PLAYBOOK

public = APIRouter(prefix="/api/v1", tags=["system"])
router = APIRouter(prefix="/api/v1", tags=["system"], dependencies=[Depends(require_api_key)])
_runtime: dict = {"worker": None, "started_at": datetime.now(timezone.utc)}


def set_worker(worker) -> None:
    _runtime["worker"] = worker


def _db_ok() -> tuple[bool, str | None]:
    try:
        with get_engine().connect() as c:
            c.execute(text("SELECT 1"))
        return True, None
    except Exception as e:
        return False, type(e).__name__


@public.get("/health", summary="Liveness and component health (no authentication)")
def health():
    ok, err = _db_ok()
    s = get_settings()
    return {"status": "ok" if ok and model_service.ready else "degraded", "version": s.app_version,
            "components": {"database": {"ok": ok, "error": err, "dialect": get_engine().dialect.name},
                           "cache": cache.healthy(), "ml": {"ok": model_service.ready},
                           "worker": {"embedded": s.embedded_worker,
                                      "running": _runtime["worker"] is not None if s.embedded_worker else None}},
            "time": datetime.now(timezone.utc).isoformat()}


@router.get("/status", summary="Detailed status of SOAR, ML, AI and CTI subsystems")
async def status(db: Session = Depends(get_db)):
    s = get_settings()
    last_run = db.scalars(select(PlaybookRun).order_by(PlaybookRun.id.desc()).limit(1)).first()
    queued = db.scalar(select(func.count()).select_from(Incident).where(Incident.status == "queued"))
    running = db.scalar(select(func.count()).select_from(Incident).where(Incident.status == "running"))
    w = _runtime["worker"]
    pb = PLAYBOOK()
    return {
        "platform": {"name": s.app_name, "version": s.app_version, "deployment_mode": s.deployment_mode,
                     "cti_mode": s.cti_mode, "started_at": _runtime["started_at"].isoformat()},
        "soar": {"engine": "sfumato-lite-soar", "playbook": pb.id, "version": pb.version, "nodes": len(pb.nodes),
                 "queued": queued, "running": running,
                 "worker": {"mode": "embedded" if s.embedded_worker else "external",
                            "id": w.worker_id if w else None, "concurrency": w.concurrency if w else None,
                            "processed": w.processed if w else None},
                 "last_run": {"status": last_run.status, "at": last_run.started_at.isoformat(),
                              "duration_ms": last_run.duration_ms} if last_run else None},
        "ml": model_service.status(),
        "ai": await resolve_provider(),
        "cti": [{k: p[k] for k in ("key", "name", "configured", "self_hosted", "hint")} for p in provider_catalog()],
        "cache": cache.healthy(),
    }


@router.get("/stats", summary="Command-center statistics")
def stats(db: Session = Depends(get_db)):
    rows = db.execute(select(Incident.status, Incident.verdict, Incident.severity, Incident.alert_timestamp,
                             Incident.duration_ms, Incident.human_review_required)).all()
    by_status = Counter(r[0] for r in rows)
    by_verdict = Counter(r[1] for r in rows if r[1])
    by_sev = Counter(r[2] for r in rows)
    durations = [r[4] for r in rows if r[4] and r[0] in ("completed", "needs_review")]
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=23)).replace(minute=0, second=0, microsecond=0)
    buckets = {(start + timedelta(hours=h)).strftime("%Y-%m-%dT%H:00"): Counter() for h in range(24)}
    for st, verdict, sev, alert_ts, *_ in rows:  # bucketed by when the alert happened
        c = alert_ts if alert_ts.tzinfo else alert_ts.replace(tzinfo=timezone.utc)
        k = c.strftime("%Y-%m-%dT%H:00")
        if k in buckets:
            buckets[k]["total"] += 1
            if verdict:
                buckets[k][verdict] += 1
    recent = db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(8)).all()
    from app.api.incidents import summary

    cti_rows = db.execute(select(CTIQuery.provider, CTIQuery.status, func.count())
                          .where(CTIQuery.queried_at >= now - timedelta(hours=24))
                          .group_by(CTIQuery.provider, CTIQuery.status)).all()
    cti_health: dict[str, dict] = {}
    for p, st, n in cti_rows:
        h = cti_health.setdefault(p, {"ok": 0, "errors": 0})
        h["ok" if st in ("ok", "no_results") else "errors"] += n
    return {
        "total": len(rows),
        "active": by_status.get("queued", 0) + by_status.get("running", 0),
        "by_status": dict(by_status),
        "verdicts": {v: by_verdict.get(v, 0) for v in ("TRUE_POSITIVE", "FALSE_POSITIVE", "LEGITIMATE_ACTIVITY",
                                                       "INCONCLUSIVE")},
        "needs_review": sum(1 for r in rows if r[5]),
        "failed": by_status.get("failed", 0),
        "avg_investigation_ms": round(sum(durations) / len(durations)) if durations else None,
        "severity": {s: by_sev.get(s, 0) for s in ("informational", "low", "medium", "high", "critical")},
        "timeline": [{"hour": k, **{kk: v for kk, v in c.items()}} for k, c in buckets.items()],
        "recent": [summary(r) for r in recent],
        "cti_health_24h": cti_health,
    }


def _scenarios_index() -> list[dict]:
    base = Path(get_settings().examples_dir) / "incidents"
    idx = base / "index.json"
    return json.loads(idx.read_text(encoding="utf-8")) if idx.exists() else []


@router.get("/scenarios", summary="Bundled demonstration scenarios")
def scenarios():
    return [{k: v for k, v in s.items() if k != "presenter_notes"} for s in _scenarios_index()]


@router.get("/scenarios/{key}", summary="Scenario JSON")
def scenario(key: str):
    s = next((s for s in _scenarios_index() if s["key"] == key), None)
    if not s:
        raise HTTPException(404, "Unknown scenario")
    path = Path(get_settings().examples_dir) / "incidents" / s["file"]
    return {**{k: v for k, v in s.items() if k != "presenter_notes"},
            "incident": json.loads(path.read_text(encoding="utf-8"))}


@router.get("/schema/incident", summary="JSON schema of the incident format")
def schema():
    return incident_json_schema()


@router.get("/settings", summary="Effective configuration (secrets are never returned)")
def get_settings_view():
    s = get_settings()
    return {"deployment_mode": s.deployment_mode, "cti_mode": s.cti_mode, "ai_provider": s.ai_provider,
            "ai_allow_external": s.ai_allow_external, "ollama_model": s.ollama_model,
            "anthropic_model": s.anthropic_model, "openai_model": s.openai_model,
            "credentials": credentials.credential_status(), "providers": provider_catalog(),
            "limits": {"max_request_bytes": s.max_request_bytes, "rate_limit_per_minute": s.rate_limit_per_minute}}


class CredentialIn(BaseModel):
    name: str
    value: str | None = Field(default=None, max_length=4096)


@router.put("/settings/credentials", summary="Store (or clear) an optional provider credential")
def put_credential(body: CredentialIn, request: Request):
    if body.name not in credentials.MANAGED:
        raise HTTPException(400, f"Unknown credential. Allowed: {', '.join(credentials.MANAGED)}")
    if body.name.endswith("_url") and body.value and not body.value.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    credentials.set_credential(body.name, body.value)
    reset_status_cache()
    audit(request, "settings.credential", body.name, {"cleared": not body.value})
    return {"name": body.name, "configured": bool(body.value)}


@router.get("/audit", summary="Recent audit log entries")
def audit_log(db: Session = Depends(get_db), limit: int = 100):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 500))).all()
    return [{"ts": r.ts.isoformat(), "actor": r.actor, "client_ip": r.client_ip, "action": r.action,
             "target": r.target, "details": r.details} for r in rows]
