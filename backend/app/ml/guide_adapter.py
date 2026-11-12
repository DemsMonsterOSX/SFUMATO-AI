"""Maps a Sfumato incident (+ the evidence gathered so far) to GUIDE-style signals."""
from __future__ import annotations

from app.schemas.evidence import Evidence
from app.schemas.incident import IncidentIn


def incident_to_guide(incident: IncidentIn, evidence: list[Evidence]) -> dict:
    categories = [incident.alert.category] if incident.alert.category else []
    techniques = sorted({t for e in evidence if e.category != "knowledge"
                         and e.polarity in ("malicious", "suspicious") for t in e.mitre})
    entities: set[str] = set()
    if incident.asset:
        entities.add("Machine")
    if incident.user:
        entities.add("User")
    if incident.process:
        entities.add("Process")
    if incident.file or (incident.process and incident.process.sha256):
        entities.add("File")
    for ind in incident.indicators:
        if ind.type.value in ("ipv4", "ipv6"):
            entities.add("Ip")
        elif ind.type.value in ("url", "domain"):
            entities.add("Url")
        elif ind.type.value in ("md5", "sha1", "sha256"):
            entities.add("File")
    n = incident.network
    if n and (n.destination_ip or n.source_ip):
        entities.add("Ip")
    if n and (n.url or n.destination_domain):
        entities.add("Url")
    a = incident.authentication
    if a and a.source_ip:
        entities.add("Ip")
    return {"categories": categories, "techniques": techniques, "entities": sorted(entities),
            "timestamp": incident.timestamp}
