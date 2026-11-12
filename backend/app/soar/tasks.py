"""Task handlers and branch predicates for the SFUMATO_AUTONOMOUS_INVESTIGATION playbook."""
from __future__ import annotations

import asyncio
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from sqlalchemy import delete, select

from app.agents.investigator import investigate, validate_output
from app.agents.schemas import AgentOutput, AgentReport
from app.core.config import get_settings
from app.cti import correlation
from app.cti import engine as cti_engine
from app.cti.base import ProviderResult
from app.database.session import session_scope
from app.decision.engine import evaluate
from app.knowledge import knowledge_base
from app.ml.features import build_features
from app.ml.guide_inference import guide_service
from app.ml.inference import model_service
from app.models import CTIQuery, Incident, TaskRun
from app.schemas.evidence import ExtractedIndicator
from app.schemas.incident import IncidentIn
from app.services import behavior, events, ioc, mitre
from app.services.evidence import EvidenceBook
from app.services.recommendations import recommend
from app.soar.engine import Playbook, PlaybookEngine

RAW_LIMIT = 200_000


@dataclass
class InvestigationContext:
    incident_pk: int
    incident_id: str
    raw: dict
    cti_mode: str
    run_id: int | None = None
    model: IncidentIn | None = None
    normalized: dict = field(default_factory=dict)
    extraction: dict = field(default_factory=dict)
    indicators: list[ExtractedIndicator] = field(default_factory=list)
    assets: dict = field(default_factory=dict)
    book: EvidenceBook = field(default_factory=EvidenceBook)
    cti: dict = field(default_factory=dict)
    cti_links: dict = field(default_factory=dict)
    cti_rows: dict = field(default_factory=dict)  # id(result) -> CTIQuery pk
    behavior: dict = field(default_factory=dict)
    features: dict = field(default_factory=dict)
    feature_meta: dict = field(default_factory=dict)
    ml: dict = field(default_factory=dict)
    ai: dict = field(default_factory=dict)
    decision: dict = field(default_factory=dict)
    recommendations: list[dict] = field(default_factory=list)
    knowledge: dict = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def indicator_dicts(self) -> list[dict]:
        return [i.model_dump() for i in self.indicators]


# ----------------------------------------------------------------------------------------------- predicates
def has_queryable_indicators(ctx: InvestigationContext) -> bool:
    providers = cti_engine.build_providers()
    return any(cti_engine._eligible(i, p, ctx.cti_mode)[0] and (ctx.cti_mode == "demo" or p.configured())
               for i in ctx.indicators for p in providers)


def has_cti_results(ctx: InvestigationContext) -> bool:
    return bool(ctx.cti.get("results"))


def human_review_required(ctx: InvestigationContext) -> bool:
    return bool(ctx.decision.get("human_review_required"))


def knowledge_available(ctx: InvestigationContext) -> bool:
    return knowledge_base.ready or knowledge_base.attach()


PREDICATES = {"has_queryable_indicators": has_queryable_indicators, "has_cti_results": has_cti_results,
              "human_review_required": human_review_required, "knowledge_available": knowledge_available}


# ------------------------------------------------------------------------------------------------- handlers
async def receive_incident(ctx: InvestigationContext, log) -> dict:
    size = len(json.dumps(ctx.raw))
    log(f"Incident {ctx.incident_id} received ({size} bytes), CTI mode: {ctx.cti_mode}")
    with session_scope() as s:  # a retried run starts from a clean CTI table for this incident
        s.execute(delete(CTIQuery).where(CTIQuery.incident_pk == ctx.incident_pk))
    return {"bytes": size, "source": ctx.raw.get("source"), "cti_mode": ctx.cti_mode}


async def validate_json(ctx: InvestigationContext, log) -> dict:
    ctx.model = IncidentIn.model_validate(ctx.raw)  # defence in depth: re-validated by the worker
    blocks = [k for k in ("asset", "user", "process", "network", "authentication", "file")
              if getattr(ctx.model, k) is not None]
    log(f"Schema valid. Context blocks present: {', '.join(blocks) or 'none'}")
    return {"valid": True, "context_blocks": blocks, "declared_indicators": len(ctx.model.indicators)}


async def normalize_incident(ctx: InvestigationContext, log) -> dict:
    m = ctx.model
    decoded = ioc.decode_powershell(m.process.command_line if m.process else None)
    ctx.normalized = {
        "incident_id": m.incident_id,
        "timestamp_utc": m.timestamp.astimezone(timezone.utc).isoformat(),
        "source": m.source.upper(), "severity": m.severity.value,
        "alert": m.alert.model_dump(),
        "asset": {"hostname": (m.asset.hostname or "").upper() or None, "ip": m.asset.ip,
                  "criticality": m.asset.criticality.value if m.asset.criticality else None,
                  "environment": m.asset.environment} if m.asset else None,
        "user": {"username": (m.user.username or "").lower() or None, "domain": m.user.domain} if m.user else None,
        "process": {"name": (m.process.name or "").lower() or None, "parent": (m.process.parent or "").lower() or None,
                    "command_line": m.process.command_line, "decoded_command": decoded,
                    "signer": m.process.signer} if m.process else None,
        "network": m.network.model_dump(exclude_none=True) if m.network else None,
        "authentication": m.authentication.model_dump(exclude_none=True) if m.authentication else None,
        "file": m.file.model_dump(exclude_none=True) if m.file else None,
        "metadata": m.metadata.model_dump(exclude_none=True),
    }
    with session_scope() as s:
        s.get(Incident, ctx.incident_pk).normalized = ctx.normalized
    if decoded:
        log("Encoded PowerShell payload decoded for static inspection (never executed)")
    return {"normalized_fields": sum(1 for v in ctx.normalized.values() if v), "decoded_command": bool(decoded)}


async def extract_indicators(ctx: InvestigationContext, log) -> dict:
    ctx.extraction = ioc.extract_indicators(ctx.model)
    ctx.indicators = [ExtractedIndicator.model_validate(i) for i in ctx.extraction["indicators"]]
    by_type = Counter(i.type for i in ctx.indicators)
    for i in ctx.indicators:
        log(f"{i.type} {i.value} — scope {i.scope}{' (shareable)' if i.shareable else ''}")
    if ctx.extraction["rejected"]:
        log(f"{len(ctx.extraction['rejected'])} malformed indicator(s) rejected", level="warning")
    return {"count": len(ctx.indicators), "by_type": dict(by_type), "indicators": ctx.indicator_dicts,
            "rejected": ctx.extraction["rejected"]}


async def classify_assets(ctx: InvestigationContext, log) -> dict:
    scopes = Counter(i.scope for i in ctx.indicators)
    internal = [i.value for i in ctx.indicators if not i.shareable]
    external = [i.value for i in ctx.indicators if i.shareable]
    asset = ctx.normalized.get("asset") or {}
    ctx.assets = {"asset": asset, "internal": internal, "external": external, "scopes": dict(scopes)}
    log(f"{len(external)} external indicator(s) eligible for public CTI; {len(internal)} kept internal")
    return ctx.assets


async def query_cti(ctx: InvestigationContext, log) -> dict:
    async def on_result(r: ProviderResult) -> None:
        pk = await asyncio.to_thread(_persist_cti, ctx.incident_pk, r)
        ctx.cti_rows[id(r)] = pk
        events.emit(ctx.incident_pk, "cti_result", f"{r.provider_name} → {r.indicator}: {r.status}/{r.verdict}",
                    stage="query_cti", status=r.status,
                    data={"provider": r.provider, "provider_name": r.provider_name, "indicator": r.indicator,
                          "indicator_type": r.indicator_type, "verdict": r.verdict, "status": r.status,
                          "data_origin": r.data_origin, "duration_ms": r.duration_ms, "summary": r.summary,
                          "error": r.error})

    with session_scope() as s:
        s.execute(delete(CTIQuery).where(CTIQuery.incident_pk == ctx.incident_pk))
    ctx.cti = await cti_engine.enrich(ctx.indicators, ctx.cti_mode, on_result)
    for p in ctx.cti["providers"]:
        if not p["configured"]:
            log(f"{p['name']} not configured — {p['hint']}", level="warning")
    for sk in ctx.cti["skipped"]:
        log(f"Not sent to {sk['provider']}: {sk['indicator']} ({sk['reason']})")
    errors = [r for r in ctx.cti["results"] if r.status not in ("ok", "no_results")]
    if ctx.cti["results"] and len(errors) == len(ctx.cti["results"]):
        log("All CTI queries failed", level="error")
    return {"mode": ctx.cti_mode, "queries": len(ctx.cti["results"]), "errors": len(errors),
            "coverage": ctx.cti["coverage"], "providers": ctx.cti["providers"], "skipped": len(ctx.cti["skipped"])}


def _persist_cti(incident_pk: int, r: ProviderResult) -> int:
    raw = r.raw
    if raw is not None and len(json.dumps(raw, default=str)) > RAW_LIMIT:
        raw = {"_truncated": True, "_note": f"raw response larger than {RAW_LIMIT} bytes"}
    with session_scope() as s:
        row = CTIQuery(incident_pk=incident_pk, provider=r.provider, indicator=r.indicator,
                       indicator_type=r.indicator_type, data_origin=r.data_origin, status=r.status, verdict=r.verdict,
                       threat_type=r.threat_type, malware=r.malware, threat_actors=r.threat_actors,
                       confidence=r.confidence, tags=r.tags, references=r.references, mitre=r.mitre,
                       relationships=r.relationships, first_seen=r.first_seen, last_seen=r.last_seen,
                       freshness_days=r.freshness_days, duration_ms=r.duration_ms, http_status=r.http_status,
                       error=r.error, raw_response=raw, queried_at=r.queried_at)
        s.add(row)
        s.flush()
        return row.id


async def correlate_cti(ctx: InvestigationContext, log) -> dict:
    out = correlation.correlate(ctx.cti["results"], ctx.book)
    ctx.cti["features"] = out["features"]
    with session_scope() as s:
        for r in ctx.cti["results"]:
            pk = ctx.cti_rows.get(id(r))
            if pk:
                s.get(CTIQuery, pk).evidence_id = out["links"].get(id(r))
    cti_ev = ctx.book.by_category("cti")
    for e in cti_ev:
        log(f"{e.id} [{e.polarity}] {e.title}")
    return {"evidence": [e.id for e in cti_ev], "malicious_indicators": out["malicious_indicators"],
            "features": out["features"]}


async def analyze_behavior(ctx: InvestigationContext, log) -> dict:
    ctx.behavior = behavior.analyze(ctx.model, ctx.book, ctx.extraction.get("decoded_command"))
    produced = [e for e in ctx.book.all() if e.category in ("behavior", "context", "integrity")]
    for e in produced:
        log(f"{e.id} [{e.polarity}] {e.title}")
    for n in ctx.behavior["notes"]:
        log(n, level="warning")
    return {"evidence": [e.id for e in produced], "telemetry": ctx.behavior["telemetry"],
            "signals": [k for k, v in ctx.behavior["features"].items() if v]}


async def generate_features(ctx: InvestigationContext, log) -> dict:
    ctx.cti.setdefault("features", {})
    ctx.features, ctx.feature_meta = build_features(ctx.model, ctx.behavior, ctx.cti, ctx.indicator_dicts)
    active = {k: v for k, v in ctx.features.items() if v}
    log(f"{len(ctx.features)} features computed, {len(active)} non-zero; completeness {ctx.feature_meta['completeness']:.0%}")
    return {"features": ctx.features, "completeness": ctx.feature_meta["completeness"],
            "sources": ctx.feature_meta["sources"], "evidence_total": len(ctx.book.all())}


async def ml_inference(ctx: InvestigationContext, log) -> dict:
    ctx.ml = await asyncio.to_thread(model_service.predict, ctx.features, ctx.feature_meta)
    if ctx.ml["status"] == "classified":
        log(f"{ctx.ml['model_name']} → {ctx.ml['label']} {ctx.ml['probabilities']}")
    else:
        log(f"ML {ctx.ml['status']}: {ctx.ml.get('reason')}", level="warning")
    ev = ctx.book.add("ml", polarity="neutral", kind="ml_result", weight=0,
                      title=f"ML {ctx.ml['status']}" + (f": {ctx.ml['label']}" if ctx.ml.get("label") else
                                                         f" ({ctx.ml.get('reason')})"),
                      description="Model output; weighted separately by the decision engine (max 15 points).",
                      source=f"ML {ctx.ml.get('model_name', 'n/a')} {ctx.ml.get('model_version', '')}",
                      data={k: ctx.ml.get(k) for k in ("probabilities", "status", "reason", "label")})
    ctx.ml["evidence_id"] = ev.id
    if await asyncio.to_thread(guide_service.ensure_loaded):
        ref = await asyncio.to_thread(guide_service.predict, ctx.model, ctx.book.all())
        ctx.ml["reference"] = ref
        log(f"GUIDE reference model: {ref['status']} "
            + (f"{ref['label']} p_threat={ref['p_threat']}" if ref["status"] == "classified" else f"({ref['reason']})"),
            level="info" if ref["status"] == "classified" else "warning")
        rev = ctx.book.add("ml", polarity="neutral", kind="ml_reference", weight=0,
                           title=f"GUIDE reference model {ref['status']}"
                                 + (f": {ref['label']}" if ref.get("label") else f" ({ref['reason']})"),
                           description="Second opinion trained on real SOC labels (Microsoft GUIDE); max 10 points.",
                           source=f"GUIDE {ref.get('model_name', '')} {ref.get('model_version', '')}",
                           data={k: ref.get(k) for k in ("probabilities", "status", "reason", "label")})
        ref["evidence_id"] = rev.id
    return {**{k: ctx.ml.get(k) for k in ("status", "reason", "label", "probabilities", "model_name", "latency_ms",
                                          "completeness")},
            "reference": {k: ctx.ml["reference"].get(k) for k in ("status", "reason", "label", "p_threat")}
            if ctx.ml.get("reference") else None}


def knowledge_query(ctx: InvestigationContext) -> str:
    """Builds the retrieval query from facts established so far (never from free-form LLM output)."""
    alert = ctx.model.alert
    parts = [alert.name, alert.category or "", (alert.description or "")[:300]]
    strong = [e for e in ctx.book.all() if e.polarity in ("malicious", "suspicious")]
    parts += [e.title for e in sorted(strong, key=lambda e: -e.weight)[:6]]
    techniques = sorted({t for e in strong for t in e.mitre})
    parts += [f"{t} {mitre.TECHNIQUES[t]['name']}" for t in techniques if mitre.is_known(t)][:6]
    parts += sorted({m for r in ctx.cti.get("results", []) for m in r.malware})[:4]
    parts += [i.value for i in ctx.indicators if i.type == "cve"]
    return " | ".join(p for p in parts if p)[:1200]


async def retrieve_knowledge(ctx: InvestigationContext, log) -> dict:
    from app.agents import prompt_guard

    query = knowledge_query(ctx)
    hits = await asyncio.to_thread(knowledge_base.search, query)
    kept, rejected = [], 0
    for h in hits:
        if prompt_guard.scan({"title": h["title"], "text": h["text"]}):
            rejected += 1  # instruction-like content: never forwarded to the LLM
            continue
        ev = ctx.book.add("knowledge", polarity="neutral", kind="kb_reference", weight=0,
                          title=h["title"][:200], description=h["text"][:600],
                          source=f"Knowledge base ({h.get('domain') or 'general'})",
                          data={"score": h["score"], "domain": h.get("domain"), "source_file": h.get("source_file"),
                                "record_id": h.get("record_id"), "techniques": h.get("techniques") or []})
        kept.append({"evidence_id": ev.id, "title": h["title"], "excerpt": h["text"][:1500], "score": h["score"],
                     "domain": h.get("domain"), "source_file": h.get("source_file"), "record_id": h.get("record_id"),
                     "techniques": h.get("techniques") or []})
        log(f"{ev.id} ({h['score']:.2f}) {h['title'][:90]}")
    st = knowledge_base.status()
    ctx.knowledge = {"status": "ok", "query": query, "passages": kept, "rejected_by_prompt_guard": rejected,
                     "store": st["store"], "dataset": st["dataset"], "version": st["version"],
                     "license": st["license"], "embedding_model": st["embedding_model"]}
    if not kept:
        log("No passage above the relevance threshold", level="warning")
    return {"passages": len(kept), "rejected": rejected, "query": query[:300]}


def _soar_history(ctx: InvestigationContext) -> list[dict]:
    with session_scope() as s:
        rows = s.scalars(select(TaskRun).where(TaskRun.run_id == ctx.run_id).order_by(TaskRun.order)).all()
        return [{"node": t.node_id, "status": t.status, "duration_ms": t.duration_ms} for t in rows]


async def invoke_ai(ctx: InvestigationContext, log) -> dict:
    ai_ctx = {"incident": ctx.raw, "indicators": ctx.indicator_dicts, "evidence": ctx.book.all(), "ml": ctx.ml,
              "soar": _soar_history(ctx), "completeness": ctx.feature_meta.get("completeness"),
              "knowledge": ctx.knowledge.get("passages", [])}
    ctx.ai = await investigate(ai_ctx, log)
    log(f"Report produced by {ctx.ai['provider']} ({ctx.ai['model']}) in {ctx.ai['latency_ms']} ms")
    if ctx.ai.get("fallback_reason"):
        log(ctx.ai["fallback_reason"], level="warning")
    return {"provider": ctx.ai["provider"], "model": ctx.ai["model"], "mode": ctx.ai["mode"],
            "latency_ms": ctx.ai["latency_ms"], "recommended_verdict": ctx.ai["recommended_verdict"],
            "fallback_reason": ctx.ai.get("fallback_reason")}


async def validate_agent_output(ctx: InvestigationContext, log) -> dict:
    report = AgentReport.model_validate(ctx.ai)
    out, stats = validate_output(AgentOutput.model_validate(report.model_dump()), ctx.book.all())
    claims = (out.suspicious_behaviors + out.cti_findings + out.supporting_evidence + out.contradictory_evidence)
    cited = {i for c in claims for i in c.evidence_ids}
    log(f"{len(claims)} claim(s) validated, citing {len(cited)} distinct evidence item(s); "
        f"{len(out.mitre_techniques)} ATT&CK technique(s) accepted")
    ctx.ai.update(out.model_dump())
    ctx.ai["validation"] = {**ctx.ai.get("validation", {}), "second_pass": stats,
                            "claims": len(claims), "cited_evidence": sorted(cited)}
    return {"claims": len(claims), "cited_evidence": len(cited), "techniques": len(out.mitre_techniques),
            "dropped": stats["dropped_claims"] + ctx.ai["validation"].get("dropped_claims", 0)}


async def compute_verdict(ctx: InvestigationContext, log) -> dict:
    crit = (ctx.normalized.get("asset") or {}).get("criticality")
    ctx.decision = evaluate(ctx.book.all(), ctx.ml, ctx.ai, crit, ctx.feature_meta.get("completeness"))
    d = ctx.decision
    log(f"Verdict {d['verdict']} — threat score {d['threat_score']}, confidence {d['confidence']}")
    for r in d["rationale"]:
        log(r)
    return {k: d[k] for k in ("verdict", "threat_score", "confidence", "human_review_required", "review_reasons")}


async def generate_actions(ctx: InvestigationContext, log) -> dict:
    ctx.recommendations = recommend(ctx.decision, ctx.book.all(), ctx.raw, ctx.indicator_dicts)
    assert all(r["display_only"] and not r["automated"] for r in ctx.recommendations)
    for r in ctx.recommendations:
        log(f"{r['priority']} {r['action']}")
    return {"count": len(ctx.recommendations), "display_only": True,
            "priorities": dict(Counter(r["priority"] for r in ctx.recommendations))}


async def route_human_review(ctx: InvestigationContext, log) -> dict:
    reasons = ctx.decision.get("review_reasons", [])
    log("Queued for analyst review: " + "; ".join(reasons))
    return {"reasons": reasons}


def _techniques(ctx: InvestigationContext) -> list[dict]:
    found: dict[str, list[str]] = {}
    for e in ctx.book.all():
        if e.polarity in ("malicious", "suspicious"):
            for t in e.mitre:
                found.setdefault(t, []).append(e.id)
    for t in ctx.ai.get("mitre_techniques", []):
        found.setdefault(t["technique_id"], []).extend(t["evidence_ids"])
    return [{**mitre.describe(t), "evidence_ids": sorted(set(ids))} for t, ids in sorted(found.items())]


def build_report(ctx: InvestigationContext) -> dict:
    results = ctx.cti.get("results", [])
    return {
        "incident_id": ctx.incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cti_mode": ctx.cti_mode,
        "playbook": {"id": PLAYBOOK().id, "version": PLAYBOOK().version, "run_id": ctx.run_id},
        "normalized": ctx.normalized,
        "indicators": ctx.indicator_dicts,
        "rejected_indicators": ctx.extraction.get("rejected", []),
        "decoded_command": ctx.extraction.get("decoded_command"),
        "assets": ctx.assets,
        "cti": {"mode": ctx.cti.get("mode", ctx.cti_mode), "providers": ctx.cti.get("providers", []),
                "skipped": ctx.cti.get("skipped", []), "coverage": ctx.cti.get("coverage", 0),
                "planned_queries": ctx.cti.get("planned_queries", 0), "features": ctx.cti.get("features", {}),
                "results": [r.model_dump(mode="json", exclude={"raw"}) for r in results]},
        "behavior": {"telemetry": ctx.behavior.get("telemetry"), "notes": ctx.behavior.get("notes"),
                     "signals": [k for k, v in ctx.behavior.get("features", {}).items() if v]},
        "evidence": ctx.book.dump(),
        "features": ctx.features, "feature_meta": ctx.feature_meta,
        "ml": ctx.ml, "ai": ctx.ai, "decision": ctx.decision,
        "recommendations": ctx.recommendations,
        "mitre": _techniques(ctx),
        "knowledge": ctx.knowledge or {"status": "unavailable", "passages": [],
                                       "reason": knowledge_base.status()["state"]},
    }


async def store_report(ctx: InvestigationContext, log) -> dict:
    report = build_report(ctx)

    def _save():
        with session_scope() as s:
            inc = s.get(Incident, ctx.incident_pk)
            inc.report = json.loads(json.dumps(report, default=str))
            inc.verdict = ctx.decision["verdict"]
            inc.threat_score = ctx.decision["threat_score"]
            inc.verdict_confidence = ctx.decision["confidence"]
            inc.human_review_required = ctx.decision["human_review_required"]

    await asyncio.to_thread(_save)
    log(f"Report stored ({len(json.dumps(report, default=str)) // 1024} KiB)")
    return {"stored": True}


async def publish_results(ctx: InvestigationContext, log) -> dict:
    now = datetime.now(timezone.utc)
    status = "needs_review" if ctx.decision["human_review_required"] else "completed"
    with session_scope() as s:
        inc = s.get(Incident, ctx.incident_pk)
        inc.status = status
        inc.completed_at = now
        started = inc.started_at or ctx.started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        inc.duration_ms = int((now - started).total_seconds() * 1000)
        duration = inc.duration_ms
    log(f"Investigation {status} in {duration} ms")
    events.emit(ctx.incident_pk, "incident", f"Investigation {status.replace('_', ' ')}", status=status,
                data={"verdict": ctx.decision["verdict"], "threat_score": ctx.decision["threat_score"],
                      "duration_ms": duration})
    return {"status": status, "duration_ms": duration}


HANDLERS = {f.__name__: f for f in (receive_incident, validate_json, normalize_incident, extract_indicators,
                                    classify_assets, query_cti, correlate_cti, analyze_behavior, generate_features,
                                    ml_inference, retrieve_knowledge, invoke_ai, validate_agent_output, compute_verdict, generate_actions,
                                    route_human_review, store_report, publish_results)}


@lru_cache
def PLAYBOOK() -> Playbook:
    return Playbook.load(Path(get_settings().playbooks_dir) / "sfumato_autonomous_investigation.yml")


def build_engine() -> PlaybookEngine:
    return PlaybookEngine(PLAYBOOK(), HANDLERS, PREDICATES)

