"""Investigation event journal. Every event is persisted; the SSE stream replays from the database,
so the dashboard only ever shows events that really happened (and works across processes)."""
from __future__ import annotations

import threading
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.database.session import session_scope
from app.models import InvestigationEvent

MILESTONES = [
    ("json_received", "JSON received"),
    ("incident_validated", "Incident validated"),
    ("indicators_extracted", "Indicators extracted"),
    ("cti_queried", "CTI providers queried"),
    ("cti_evidence_received", "CTI evidence received"),
    ("soar_correlation_completed", "SOAR correlation completed"),
    ("ml_classification_completed", "ML classification completed"),
    ("ai_investigation_completed", "AI investigation completed"),
    ("final_verdict_generated", "Final verdict generated"),
    ("recommended_actions_available", "Recommended actions available"),
]
MILESTONE_LABELS = dict(MILESTONES)

_lock = threading.Lock()


def emit(incident_pk: int, type_: str, message: str, stage: str | None = None, status: str | None = None,
         data: dict[str, Any] | None = None) -> int:
    # The per-process lock serialises writers; the unique (incident, seq) constraint plus retry covers
    # the rare case of the API process and a worker process writing for the same incident at once.
    for attempt in range(5):
        try:
            with _lock, session_scope() as s:
                seq = (s.scalar(select(func.max(InvestigationEvent.seq))
                                .where(InvestigationEvent.incident_pk == incident_pk)) or 0) + 1
                s.add(InvestigationEvent(incident_pk=incident_pk, seq=seq, type=type_, stage=stage, status=status,
                                         message=message[:4000], data=data))
            return seq
        except IntegrityError:
            if attempt == 4:
                raise
    return -1


def milestone(incident_pk: int, key: str, data: dict[str, Any] | None = None) -> None:
    emit(incident_pk, "milestone", MILESTONE_LABELS[key], stage=key, status="completed", data=data)


def serialize(ev: InvestigationEvent) -> dict:
    return {"seq": ev.seq, "ts": ev.ts.isoformat() if ev.ts else None, "type": ev.type, "stage": ev.stage,
            "status": ev.status, "message": ev.message, "data": ev.data}


def list_events(incident_pk: int, after: int = 0, limit: int = 1000) -> list[dict]:
    with session_scope() as s:
        rows = s.scalars(select(InvestigationEvent)
                         .where(InvestigationEvent.incident_pk == incident_pk, InvestigationEvent.seq > after)
                         .order_by(InvestigationEvent.seq).limit(limit)).all()
        return [serialize(r) for r in rows]
