"""Incident ingestion: persists a validated incident and queues it for investigation."""
from __future__ import annotations

from sqlalchemy import func, select

from app.core.config import get_settings
from app.database.session import session_scope
from app.models import Incident
from app.schemas.incident import IncidentIn
from app.services import events


class DuplicateIncident(Exception):
    pass


def submit(incident: IncidentIn, cti_mode: str | None = None, via: str = "api", resubmit: bool = False) -> Incident:
    mode = cti_mode or get_settings().cti_mode
    raw = incident.model_dump(mode="json", exclude_none=True)
    with session_scope() as s:
        iid = incident.incident_id
        if s.scalar(select(Incident.id).where(Incident.incident_id == iid)):
            if not resubmit:
                raise DuplicateIncident(iid)
            n = s.scalar(select(func.count()).select_from(Incident).where(Incident.incident_id.like(f"{iid}-R%"))) or 0
            iid = f"{iid}-R{n + 2}"
            raw["incident_id"] = iid
        inc = Incident(incident_id=iid, source=incident.source, severity=incident.severity.value,
                       alert_name=incident.alert.name, alert_timestamp=incident.timestamp, raw=raw, cti_mode=mode,
                       submitted_via=via, status="queued")
        s.add(inc)
        s.flush()
        pk = inc.id
    events.emit(pk, "incident", "Incident accepted for investigation", status="queued",
                data={"incident_id": iid, "cti_mode": mode, "submitted_via": via})
    with session_scope() as s:
        return s.get(Incident, pk)
