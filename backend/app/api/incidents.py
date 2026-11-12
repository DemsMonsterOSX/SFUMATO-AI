"""Incident ingestion and investigation endpoints."""
from __future__ import annotations

import asyncio
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.security import audit, require_api_key
from app.database.session import get_db
from app.models import CTIQuery, Incident, PlaybookRun
from app.schemas.incident import IncidentAccepted, IncidentIn
from app.services import events, ingestion

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"], dependencies=[Depends(require_api_key)])

TERMINAL = {"completed", "needs_review", "failed"}


def _get(db: Session, incident_id: str) -> Incident:
    inc = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not inc:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return inc


def summary(inc: Incident) -> dict:
    return {
        "incident_id": inc.incident_id, "status": inc.status, "source": inc.source, "severity": inc.severity,
        "alert_name": inc.alert_name, "timestamp": inc.alert_timestamp.isoformat() if inc.alert_timestamp else None,
        "cti_mode": inc.cti_mode, "submitted_via": inc.submitted_via, "verdict": inc.verdict,
        "threat_score": inc.threat_score, "verdict_confidence": inc.verdict_confidence,
        "human_review_required": inc.human_review_required, "created_at": inc.created_at.isoformat(),
        "completed_at": inc.completed_at.isoformat() if inc.completed_at else None, "duration_ms": inc.duration_ms,
        "error": inc.error, "hostname": (inc.raw.get("asset") or {}).get("hostname"),
        "attempts": inc.attempts,
    }


@router.post("", status_code=202, response_model=IncidentAccepted,
             summary="Submit an incident for autonomous investigation")
def create_incident(incident: IncidentIn, request: Request,
                    cti_mode: Literal["live", "demo"] | None = Query(None, description="Override the default CTI mode"),
                    resubmit: bool = Query(False, description="If the ID exists, store a new run as <id>-R<n>"),
                    via: Literal["api", "simulator"] = Query("api")):
    try:
        inc = ingestion.submit(incident, cti_mode, via, resubmit)
    except ingestion.DuplicateIncident:
        raise HTTPException(409, f"Incident {incident.incident_id} already exists. Use ?resubmit=true to "
                                 "investigate it again under a new ID.")
    audit(request, "incident.submit", inc.incident_id, {"cti_mode": inc.cti_mode, "via": via})
    return IncidentAccepted(incident_id=inc.incident_id, status="queued", message="Incident accepted for investigation")


@router.get("", summary="List incidents")
def list_incidents(db: Session = Depends(get_db), limit: int = Query(50, le=500), offset: int = 0,
                   status: str | None = None, verdict: str | None = None, q: str | None = None):
    stmt = select(Incident)
    if status:
        stmt = stmt.where(Incident.status == status)
    if verdict:
        stmt = stmt.where(Incident.verdict == verdict)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Incident.incident_id.ilike(like), Incident.alert_name.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Incident.created_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "items": [summary(r) for r in rows]}


@router.get("/{incident_id}", summary="Incident detail with report and playbook execution")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = _get(db, incident_id)
    return {**summary(inc), "raw": inc.raw, "normalized": inc.normalized, "report": inc.report,
            "soar": _runs(db, inc.id)}


@router.get("/{incident_id}/report", summary="Final investigation report")
def get_report(incident_id: str, db: Session = Depends(get_db)):
    inc = _get(db, incident_id)
    if inc.status not in TERMINAL:
        raise HTTPException(409, f"Investigation is {inc.status}; report not available yet")
    if not inc.report:
        raise HTTPException(404, f"No report: investigation {inc.status}" + (f" ({inc.error})" if inc.error else ""))
    return inc.report


def _runs(db: Session, pk: int) -> list[dict]:
    runs = db.scalars(select(PlaybookRun).where(PlaybookRun.incident_pk == pk).order_by(PlaybookRun.id)).all()
    return [{"run_id": r.id, "playbook": r.playbook, "version": r.playbook_version, "status": r.status,
             "attempt": r.attempt, "started_at": r.started_at.isoformat(),
             "completed_at": r.completed_at.isoformat() if r.completed_at else None, "duration_ms": r.duration_ms,
             "error": r.error,
             "tasks": [{"node_id": t.node_id, "name": t.name, "order": t.order, "status": t.status,
                        "attempts": t.attempts, "started_at": t.started_at.isoformat() if t.started_at else None,
                        "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                        "duration_ms": t.duration_ms, "logs": t.logs, "output": t.output, "error": t.error}
                       for t in r.tasks]} for r in runs]


@router.get("/{incident_id}/soar", summary="Playbook executions and task logs")
def get_soar(incident_id: str, db: Session = Depends(get_db)):
    return _runs(db, _get(db, incident_id).id)


@router.get("/{incident_id}/cti", summary="CTI queries with raw provider responses")
def get_cti(incident_id: str, db: Session = Depends(get_db), include_raw: bool = True):
    inc = _get(db, incident_id)
    rows = db.scalars(select(CTIQuery).where(CTIQuery.incident_pk == inc.id).order_by(CTIQuery.id)).all()
    cols = [c.name for c in CTIQuery.__table__.columns if c.name not in ("incident_pk",)]
    out = []
    for r in rows:
        d = {c: getattr(r, c) for c in cols}
        d["queried_at"] = r.queried_at.isoformat()
        if not include_raw:
            d.pop("raw_response")
        out.append(d)
    return out


@router.get("/{incident_id}/events", summary="Stored investigation event history")
def get_events(incident_id: str, after: int = 0, db: Session = Depends(get_db)):
    inc = _get(db, incident_id)
    return {"incident_id": incident_id, "status": inc.status, "events": events.list_events(inc.id, after)}


@router.get("/{incident_id}/events/stream", summary="Server-Sent Events stream of investigation events")
async def stream_events(incident_id: str, request: Request, after: int = 0):
    from app.database.session import session_scope

    def lookup():
        with session_scope() as s:
            inc = s.scalar(select(Incident).where(Incident.incident_id == incident_id))
            return (inc.id, inc.status) if inc else (None, None)

    pk, _ = await asyncio.to_thread(lookup)
    if pk is None:
        raise HTTPException(404, f"Incident {incident_id} not found")

    async def gen():
        last = after
        idle = 0
        yield "retry: 2000\n\n"
        while True:
            if await request.is_disconnected():
                return
            batch = await asyncio.to_thread(events.list_events, pk, last)
            for ev in batch:
                last = ev["seq"]
                yield f"id: {ev['seq']}\nevent: investigation\ndata: {json.dumps(ev, default=str)}\n\n"
            _, status = await asyncio.to_thread(lookup)
            if status in TERMINAL and not batch:
                yield f"event: end\ndata: {json.dumps({'status': status})}\n\n"
                return
            idle = 0 if batch else idle + 1
            if idle and idle % 40 == 0:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
