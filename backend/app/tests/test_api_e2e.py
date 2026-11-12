"""API, persistence and complete end-to-end investigations (offline, demo CTI, deterministic AI)."""
import inspect
import json
import re
from pathlib import Path

import pytest
import respx

from app.database.session import reset_engine, session_scope
from app.models import CTIQuery, Incident
from app.tests.conftest import HEADERS, REPO, load_scenario, run_pending_jobs


def test_health_is_public_and_api_requires_key(client):
    assert client.get("/api/v1/health").json()["components"]["database"]["ok"] is True
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.get("/api/v1/incidents", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/incidents", headers=HEADERS).status_code == 200


def test_ingestion_validation_size_limit_and_duplicates(client):
    inc = load_scenario("insufficient_evidence", "API-T-0001")
    r = client.post("/api/v1/incidents", json=inc, headers=HEADERS)
    assert r.status_code == 202
    assert r.json() == {"incident_id": "API-T-0001", "status": "queued", "message": "Incident accepted for investigation"}
    assert client.post("/api/v1/incidents", json=inc, headers=HEADERS).status_code == 409
    again = client.post("/api/v1/incidents?resubmit=true", json=inc, headers=HEADERS).json()
    assert again["incident_id"] == "API-T-0001-R2"

    bad = dict(inc, severity="urgent", incident_id="API-T-0002")
    r = client.post("/api/v1/incidents", json=bad, headers=HEADERS)
    assert r.status_code == 422 and r.json()["errors"][0]["loc"].endswith("severity")

    huge = json.dumps(dict(inc, incident_id="API-T-0003")) + " " * 300_000  # > 256 KiB default limit
    assert client.post("/api/v1/incidents", content=huge, headers={**HEADERS, "Content-Type": "application/json"}).status_code == 413

    item = client.get("/api/v1/incidents/API-T-0001", headers=HEADERS).json()
    assert item["status"] == "queued"
    assert client.get("/api/v1/incidents/API-T-0001/report", headers=HEADERS).status_code == 409
    run_pending_jobs()


def _investigate(client, scenario: str, iid: str) -> dict:
    r = client.post("/api/v1/incidents?cti_mode=demo", json=load_scenario(scenario, iid), headers=HEADERS)
    assert r.status_code == 202
    assert run_pending_jobs() >= 1
    return client.get(f"/api/v1/incidents/{iid}/report", headers=HEADERS).json()


@pytest.mark.parametrize("scenario,expected", [
    ("suspicious_powershell", "TRUE_POSITIVE"),
    ("legitimate_admin", "LEGITIMATE_ACTIVITY"),
    ("insufficient_evidence", "INCONCLUSIVE"),
    ("known_benign_software", "FALSE_POSITIVE"),
    ("malicious_domain", "TRUE_POSITIVE"),
    ("suspicious_authentication", "TRUE_POSITIVE"),
])
def test_end_to_end_scenarios_offline(client, scenario, expected):
    iid = f"E2E-{scenario}"
    with respx.mock(assert_all_mocked=True):  # any real HTTP call would raise: the demo must work offline
        rep = _investigate(client, scenario, iid)
    d = rep["decision"]
    assert d["verdict"] == expected, d["rationale"]
    assert 0 <= d["threat_score"] <= 100 and 5 <= d["confidence"] <= 99
    assert rep["ai"]["provider"] == "deterministic"
    assert rep["recommendations"] and all(r["display_only"] and not r["automated"] for r in rep["recommendations"])
    # every cited evidence ID exists
    ids = {e["id"] for e in rep["evidence"]}
    for section in ("suspicious_behaviors", "cti_findings", "supporting_evidence", "contradictory_evidence"):
        for claim in rep["ai"][section]:
            assert set(claim["evidence_ids"]) <= ids
    # all CTI answers in demo mode are labelled as fixtures
    assert all(r["data_origin"] == "demo_fixture" for r in rep["cti"]["results"])

    detail = client.get(f"/api/v1/incidents/{iid}", headers=HEADERS).json()
    assert detail["status"] in ("completed", "needs_review") and detail["verdict"] == expected
    run = detail["soar"][-1]
    assert run["status"] == "completed" and len(run["tasks"]) == 18
    assert all(t["status"] in ("completed", "skipped") for t in run["tasks"])

    ev = client.get(f"/api/v1/incidents/{iid}/events", headers=HEADERS).json()["events"]
    milestones = [e["stage"] for e in ev if e["type"] == "milestone"]
    assert milestones[0] == "json_received" and milestones[-1] == "recommended_actions_available"
    assert [e["seq"] for e in ev] == sorted(e["seq"] for e in ev)


def test_specific_scenario_expectations(client):
    rep = _investigate(client, "suspicious_powershell", "E2E-DETAIL-1")
    kinds = {e["kind"] for e in rep["evidence"]}
    assert {"office_spawns_interpreter", "encoded_command", "download_cradle", "cti_malicious"} <= kinds
    assert rep["ml"]["status"] == "classified" and rep["ml"]["label"] == "true_positive"
    assert any(t["id"] == "T1059.001" for t in rep["mitre"])
    # the private asset IP was never queried against public providers
    with session_scope() as s:
        pk = s.query(Incident.id).filter(Incident.incident_id == "E2E-DETAIL-1").scalar()
        providers = {q.provider for q in s.query(CTIQuery).filter(CTIQuery.incident_pk == pk,
                                                                   CTIQuery.indicator == "192.168.1.42")}
    assert providers <= {"opencti"}  # only the self-hosted platform

    inj = _investigate(client, "prompt_injection", "E2E-DETAIL-2")
    assert inj["decision"]["verdict"] == "TRUE_POSITIVE"
    assert "prompt-injection content detected in the incident" in inj["decision"]["review_reasons"]


def test_sse_stream_replays_persisted_events(client):
    _investigate(client, "known_benign_software", "E2E-SSE-1")
    with client.stream("GET", "/api/v1/incidents/E2E-SSE-1/events/stream", headers=HEADERS) as r:
        body = "".join(r.iter_text())
    assert "event: investigation" in body and "event: end" in body
    assert body.count("event: investigation") == len(client.get("/api/v1/incidents/E2E-SSE-1/events", headers=HEADERS).json()["events"])


def test_dashboard_endpoints(client):
    _investigate(client, "legitimate_admin", "E2E-DASH-1")
    stats = client.get("/api/v1/stats", headers=HEADERS).json()
    assert stats["total"] >= 1 and stats["verdicts"]["LEGITIMATE_ACTIVITY"] >= 1 and len(stats["timeline"]) == 24
    for path in ("status", "cti/status", "cti/indicators", "cti/graph", "soar/playbooks", "soar/runs", "ml/model",
                 "ai/status", "observatory/recent", "scenarios", "scenarios/suspicious_powershell", "settings", "audit",
                 "schema/incident"):
        assert client.get(f"/api/v1/{path}", headers=HEADERS).status_code == 200, path
    assert client.get("/api/v1/soar/playbooks", headers=HEADERS).json()[0]["id"] == "SFUMATO_AUTONOMOUS_INVESTIGATION"


def test_credentials_are_write_only_and_encrypted(client):
    r = client.put("/api/v1/settings/credentials", json={"name": "otx_api_key", "value": "super-secret-value"}, headers=HEADERS)
    assert r.status_code == 200
    body = client.get("/api/v1/settings", headers=HEADERS).text
    assert "super-secret-value" not in body and '"otx_api_key"' in body
    from app.models import ProviderCredential

    with session_scope() as s:
        stored = s.query(ProviderCredential).filter_by(name="otx_api_key").one().encrypted_value
    assert "super-secret-value" not in stored
    client.put("/api/v1/settings/credentials", json={"name": "otx_api_key", "value": None}, headers=HEADERS)
    assert client.put("/api/v1/settings/credentials", json={"name": "evil", "value": "x"}, headers=HEADERS).status_code == 400


def test_persistence_survives_new_engine(client):
    _investigate(client, "insufficient_evidence", "E2E-PERSIST-1")
    reset_engine()  # simulates a restart: brand new connection pool
    r = client.get("/api/v1/incidents/E2E-PERSIST-1/report", headers=HEADERS)
    assert r.status_code == 200 and r.json()["decision"]["verdict"] == "INCONCLUSIVE"


def test_stale_running_jobs_are_recovered():
    from datetime import datetime, timedelta, timezone

    from app.workers.worker import Worker

    with session_scope() as s:
        inc = Incident(incident_id="STALE-1", source="t", severity="low", alert_name="t",
                       alert_timestamp=datetime.now(timezone.utc), raw=load_scenario("insufficient_evidence", "STALE-1"),
                       cti_mode="demo", submitted_via="test", status="running", attempts=1,
                       heartbeat_at=datetime.now(timezone.utc) - timedelta(hours=1))
        s.add(inc)
    assert Worker().recover_stale() >= 1
    with session_scope() as s:
        assert s.query(Incident).filter_by(incident_id="STALE-1").one().status == "queued"
    run_pending_jobs()
    with session_scope() as s:
        assert s.query(Incident).filter_by(incident_id="STALE-1").one().verdict == "INCONCLUSIVE"


def test_no_automatic_remediation_anywhere():
    """Static guarantees: no remediation handler, no write calls to providers, recommendations display-only."""
    from app.soar.tasks import HANDLERS, PLAYBOOK

    forbidden = re.compile(r"block|isolat|quarantin|disable|firewall|kill|remediat", re.IGNORECASE)
    assert not [h for h in HANDLERS if forbidden.search(h)]
    assert not [n.id for n in PLAYBOOK().nodes if forbidden.search(n.handler)]
    assert PLAYBOOK().remediation == "none"
    import app.cti.abusech as a
    import app.cti.cisa_kev as k
    import app.cti.opencti as o
    import app.cti.otx as x

    for mod in (a, k, o, x):
        src = inspect.getsource(mod)
        assert not re.search(r"\.(put|patch|delete)\(", src), mod.__name__
    oc = inspect.getsource(o)
    assert "mutation" not in oc.lower()  # OpenCTI is queried, never modified
    # commands from incidents are never executed: no subprocess / os.system / eval in the backend
    backend = Path(REPO / "backend" / "app")
    for f in backend.rglob("*.py"):
        if "tests" in f.parts:
            continue
        src = f.read_text(encoding="utf-8")
        assert not re.search(r"\bsubprocess\b|os\.system\(|(?<![\w\-])(?:eval|exec)\(", src), f
