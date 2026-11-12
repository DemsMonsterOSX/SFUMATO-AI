"""Threat intelligence, SOAR, ML and AI observability endpoints."""
from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agents.providers import resolve_provider
from app.core.config import get_settings
from app.core.security import audit, require_api_key
from app.cti.engine import provider_catalog
from app.database.session import get_db
from app.knowledge import knowledge_base
from app.ml.guide_inference import guide_service
from app.ml.inference import model_service
from app.models import CTIQuery, Incident, PlaybookRun, TaskRun
from app.services import mitre
from app.soar.tasks import PLAYBOOK

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])
SEVERITY_RANK = {"malicious": 4, "suspicious": 3, "allowlisted": 1, "unknown": 2, "not_found": 0}


@router.get("/cti/status", tags=["cti"], summary="CTI providers, configuration and recent health")
def cti_status(db: Session = Depends(get_db)):
    settings = get_settings()
    rows = db.execute(select(CTIQuery.provider, CTIQuery.status, CTIQuery.data_origin, func.count(),
                             func.avg(CTIQuery.duration_ms), func.max(CTIQuery.queried_at))
                      .group_by(CTIQuery.provider, CTIQuery.status, CTIQuery.data_origin)).all()
    health: dict[str, dict] = defaultdict(lambda: {"queries": 0, "ok": 0, "errors": 0, "by_origin": {},
                                                   "avg_latency_ms": None, "last_query": None, "last_errors": []})
    lat: dict[str, list] = defaultdict(list)
    for provider, status, origin, n, avg, last in rows:
        h = health[provider]
        h["queries"] += n
        h["ok" if status in ("ok", "no_results") else "errors"] += n
        h["by_origin"][origin] = h["by_origin"].get(origin, 0) + n
        if avg is not None:
            lat[provider].append((avg, n))
        if last and (h["last_query"] is None or last.isoformat() > h["last_query"]):
            h["last_query"] = last.isoformat()
    for p, vals in lat.items():
        tot = sum(n for _, n in vals)
        health[p]["avg_latency_ms"] = round(sum(a * n for a, n in vals) / tot, 1) if tot else None
    errs = db.execute(select(CTIQuery.provider, CTIQuery.error, CTIQuery.queried_at)
                      .where(CTIQuery.error.is_not(None)).order_by(CTIQuery.id.desc()).limit(30)).all()
    for p, e, ts in errs:
        if len(health[p]["last_errors"]) < 3:
            health[p]["last_errors"].append({"error": e, "at": ts.isoformat()})
    catalog = provider_catalog()
    for c in catalog:
        c["health"] = health.get(c["key"], {"queries": 0, "ok": 0, "errors": 0, "by_origin": {},
                                            "avg_latency_ms": None, "last_query": None, "last_errors": []})
    return {"default_mode": settings.cti_mode, "deployment_mode": settings.deployment_mode, "providers": catalog,
            "privacy": "Private, internal, personal and documentation indicators are never sent to public providers."}


@router.get("/cti/indicators", tags=["cti"], summary="All queried indicators aggregated across incidents")
def cti_indicators(db: Session = Depends(get_db), limit: int = 2000):
    rows = db.execute(select(CTIQuery, Incident.incident_id).join(Incident, Incident.id == CTIQuery.incident_pk)
                      .order_by(CTIQuery.id.desc()).limit(limit)).all()
    agg: dict[tuple, dict] = {}
    for q, iid in rows:
        key = (q.indicator_type, q.indicator)
        a = agg.setdefault(key, {"indicator": q.indicator, "type": q.indicator_type, "verdict": "not_found",
                                 "providers": {}, "malware": set(), "threat_actors": set(), "mitre": set(),
                                 "tags": set(), "incidents": set(), "origins": set(), "last_queried": None,
                                 "max_confidence": None})
        if SEVERITY_RANK.get(q.verdict, 0) > SEVERITY_RANK.get(a["verdict"], 0):
            a["verdict"] = q.verdict
        if q.provider not in a["providers"]:
            a["providers"][q.provider] = {"verdict": q.verdict, "status": q.status, "confidence": q.confidence,
                                          "queried_at": q.queried_at.isoformat(), "data_origin": q.data_origin,
                                          "first_seen": q.first_seen, "last_seen": q.last_seen,
                                          "references": (q.references or [])[:5], "error": q.error,
                                          "duration_ms": q.duration_ms}
        a["malware"].update(q.malware or [])
        a["threat_actors"].update(q.threat_actors or [])
        a["mitre"].update(q.mitre or [])
        a["tags"].update((q.tags or [])[:10])
        a["incidents"].add(iid)
        a["origins"].add(q.data_origin)
        if q.confidence is not None:
            a["max_confidence"] = max(a["max_confidence"] or 0, q.confidence)
        ts = q.queried_at.isoformat()
        a["last_queried"] = max(a["last_queried"] or ts, ts)
    out = []
    for a in agg.values():
        for k in ("malware", "threat_actors", "mitre", "tags", "incidents", "origins"):
            a[k] = sorted(a[k])
        a["mitre"] = [mitre.describe(t) for t in a["mitre"]]
        out.append(a)
    out.sort(key=lambda a: (-SEVERITY_RANK.get(a["verdict"], 0), a["indicator"]))
    return out


@router.get("/cti/graph", tags=["cti"], summary="Relationship graph built from real CTI results")
def cti_graph(incident_id: str | None = None, db: Session = Depends(get_db)):
    stmt = select(CTIQuery, Incident.incident_id).join(Incident, Incident.id == CTIQuery.incident_pk)
    if incident_id:
        stmt = stmt.where(Incident.incident_id == incident_id)
    rows = db.execute(stmt.order_by(CTIQuery.id.desc()).limit(1500)).all()
    nodes: dict[str, dict] = {}
    edges: set[tuple] = set()

    def node(nid, label, kind, **extra):
        nodes.setdefault(nid, {"id": nid, "label": label, "kind": kind, **extra})

    for q, iid in rows:
        if q.verdict not in ("malicious", "suspicious", "allowlisted") and not q.relationships:
            continue
        node(f"inc:{iid}", iid, "incident")
        ind = f"ioc:{q.indicator}"
        node(ind, q.indicator, "indicator", indicator_type=q.indicator_type)
        edges.add((f"inc:{iid}", ind, "observed"))
        for m in q.malware or []:
            node(f"mal:{m}", m, "malware")
            edges.add((ind, f"mal:{m}", f"associated ({q.provider})"))
        for a in q.threat_actors or []:
            node(f"act:{a}", a, "threat_actor")
            edges.add((ind, f"act:{a}", f"attributed ({q.provider})"))
        for t in q.mitre or []:
            node(f"ttp:{t}", f"{t} {mitre.describe(t)['name']}", "attack_pattern")
            edges.add((ind, f"ttp:{t}", f"uses ({q.provider})"))
        for r in q.relationships or []:
            if r.get("target"):
                node(f"rel:{r['target']}", r["target"], (r.get("target_type") or "object").lower())
                edges.add((ind, f"rel:{r['target']}", r.get("type") or "related-to"))
    return {"nodes": list(nodes.values()),
            "edges": [{"source": s, "target": t, "label": label} for s, t, label in sorted(edges)]}


@router.get("/soar/playbooks", tags=["soar"], summary="Executable playbooks and execution statistics")
def soar_playbooks(db: Session = Depends(get_db)):
    pb = PLAYBOOK()
    counts = dict(db.execute(select(PlaybookRun.status, func.count()).where(PlaybookRun.playbook == pb.id)
                             .group_by(PlaybookRun.status)).all())
    avg = db.scalar(select(func.avg(PlaybookRun.duration_ms)).where(PlaybookRun.status == "completed"))
    node_stats = {}
    for node_id, status, n, avg_ms in db.execute(select(TaskRun.node_id, TaskRun.status, func.count(),
                                                       func.avg(TaskRun.duration_ms))
                                                .group_by(TaskRun.node_id, TaskRun.status)).all():
        ns = node_stats.setdefault(node_id, {"runs": 0, "by_status": {}, "avg_ms": None})
        ns["runs"] += n
        ns["by_status"][status] = n
        if status == "completed" and avg_ms is not None:
            ns["avg_ms"] = round(float(avg_ms), 1)
    return [{**pb.to_dict(), "engine": "sfumato-lite-soar", "executions": counts,
             "avg_duration_ms": round(float(avg), 1) if avg else None, "node_stats": node_stats}]


@router.get("/soar/runs", tags=["soar"], summary="Recent playbook executions")
def soar_runs(db: Session = Depends(get_db), limit: int = 30):
    rows = db.execute(select(PlaybookRun, Incident.incident_id).join(Incident, Incident.id == PlaybookRun.incident_pk)
                      .order_by(PlaybookRun.id.desc()).limit(limit)).all()
    return [{"run_id": r.id, "incident_id": iid, "status": r.status, "attempt": r.attempt,
             "started_at": r.started_at.isoformat(), "duration_ms": r.duration_ms, "error": r.error,
             "tasks": [{"node_id": t.node_id, "status": t.status, "duration_ms": t.duration_ms} for t in r.tasks]}
            for r, iid in rows]


@router.get("/ml/model", tags=["ml"], summary="Active model, dataset and evaluation metrics")
def ml_model():
    return {"status": model_service.status(), "metrics": model_service.metrics}


@router.post("/ml/reload", tags=["ml"], summary="Reload (or retrain if incompatible) the model artifact")
def ml_reload():
    model_service.load()
    if not model_service.ready:
        raise HTTPException(500, model_service.error)
    return model_service.status()


@router.get("/ai/status", tags=["ai"], summary="AI investigator provider selection and recent latency")
async def ai_status():
    return await resolve_provider()


@router.get("/observatory/recent", tags=["ml"], summary="Recent ML and AI outputs")
def observatory_recent(db: Session = Depends(get_db), limit: int = 20):
    rows = db.scalars(select(Incident).where(Incident.report.is_not(None)).order_by(Incident.id.desc()).limit(limit)).all()
    out = []
    for r in rows:
        rep = r.report or {}
        ml, ai, d = rep.get("ml", {}), rep.get("ai", {}), rep.get("decision", {})
        out.append({"incident_id": r.incident_id, "alert_name": r.alert_name, "verdict": r.verdict,
                    "ml_status": ml.get("status"), "ml_label": ml.get("label") or ml.get("top_label"),
                    "ml_reason": ml.get("reason"), "ml_probabilities": ml.get("probabilities"),
                    "ml_latency_ms": ml.get("latency_ms"), "ai_provider": ai.get("provider"),
                    "ai_model": ai.get("model"), "ai_latency_ms": ai.get("latency_ms"),
                    "ai_verdict": ai.get("recommended_verdict"), "ai_fallback": ai.get("fallback_reason"),
                    "ml_vote": d.get("ml_vote"), "ai_vote": d.get("ai_vote")})
    return out


@router.get("/knowledge/status", tags=["knowledge"], summary="Knowledge base (RAG) status")
def knowledge_status():
    return knowledge_base.status()


@router.post("/knowledge/sync", tags=["knowledge"], summary="Download (if configured) and reload the knowledge base")
def knowledge_sync(request: Request):
    if knowledge_base.state in ("syncing", "loading"):
        raise HTTPException(409, "A synchronisation is already running")
    knowledge_base.start_background_sync()
    audit(request, "knowledge.sync")
    return {"started": True}


@router.get("/knowledge/search", tags=["knowledge"], summary="Semantic search in the knowledge base")
def knowledge_search(q: str = Query(min_length=3, max_length=500), k: int = Query(5, ge=1, le=20),
                     min_score: float = Query(0.0, ge=0, le=1)):
    if not knowledge_base.ready:
        raise HTTPException(409, f"Knowledge base not ready ({knowledge_base.state})")
    hits = knowledge_base.search(q, k=k, min_score=min_score)
    return {"query": q, "results": [{k_: h.get(k_) for k_ in ("title", "text", "domain", "score", "source_file",
                                                              "record_id", "techniques")} for h in hits]}


@router.get("/ml/guide", tags=["ml"], summary="Reference model trained on Microsoft GUIDE (bucket) and its metrics")
def ml_guide():
    return {"status": guide_service.status(), "metrics": guide_service.metrics}


@router.post("/ml/guide/sync", tags=["ml"], summary="Fetch the newest model published in the bucket")
def ml_guide_sync(request: Request):
    if guide_service.state == "loading":
        raise HTTPException(409, "A synchronisation is already running")
    guide_service.start_background_sync()
    audit(request, "ml.guide.sync")
    return {"started": True}
