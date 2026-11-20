"""Big Data lab: pipeline description and the figures produced by the Spark job (ml/bigdata/results.json).

Nothing is invented here: when the Spark job has not been run and published, `results` is null and the page says so.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.agents.providers import CALLERS, LLMError, llm_slot, resolve_agent_provider, resolve_provider
from app.core.ttlcache import ttl_cache
from app.core.security import require_api_key
from app.services import cve as cve_lib
from app.services import datasets as ds_lib
from app.services import docs_index
from app.services import davinci
from app.services import procedures as proc_lib

router = APIRouter(prefix="/api/v1/bigdata", tags=["bigdata"], dependencies=[Depends(require_api_key)])

STAGES = [
    {"id": "acquire", "phase": "Phase 1", "title": "Acquisition", "tech": "Cloud Storage",
     "what": "10 CSV files of CSE-CIC-IDS2018 (6.9 GB) streamed from a public bucket into the project's own bucket."},
    {"id": "batch", "phase": "Phase 2", "title": "Batch processing", "tech": "Spark on Dataproc Serverless",
     "what": "Union of two CSV layouts, removal of embedded headers, Infinity/NaN and negative durations, Parquet partitioned by day."},
    {"id": "sql", "phase": "Phase 2", "title": "SQL analytics", "tech": "BigQuery",
     "what": "OLAP queries over the clean Parquet: class balance, attacks per day and hour, behavioural fingerprints, targeted ports."},
    {"id": "ml", "phase": "Phase 4", "title": "Machine learning", "tech": "Spark MLlib",
     "what": "Random Forest on a random split and a time hold-out; multiclass; leave-one-family-out vs a KMeans anomaly detector."},
    {"id": "viz", "phase": "Phase 5", "title": "Visualisation", "tech": "This page + report.py",
     "what": "Charts built only from results.json."},
]


def _results_path(name: str = "results.json") -> Path:
    return Path(get_settings().repo_dir) / "ml" / "bigdata" / name


def _load(name: str):
    p = _results_path(name)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


@router.get("/overview", summary="Pipeline stages, dataset facts and the Spark results when they have been published")
@ttl_cache(30)
def overview():
    results = _load("results.json")
    return {
        "dataset": {"name": "CSE-CIC-IDS2018 (processed traffic for ML)", "size_gb": 6.89, "files": 10,
                    "source": "AWS Open Data, Canadian Institute for Cybersecurity + CSE", "domain": "network intrusion detection"},
        "stages": STAGES,
        "results": results,
        "advanced": _load("advanced.json"),
        "attacks_by_day": _load("attacks_by_day.json"),
        "results_published": results is not None,
    }


@router.get("/scalability", summary="Measured scalability: Spark executors, Kafka scorers, API concurrency (ml/scale/*.json)")
@ttl_cache(30)
def scalability():
    d = Path(get_settings().repo_dir) / "ml" / "scale"

    def read(name: str):
        try:
            return json.loads((d / name).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            return None

    api = {}
    for kind in ("before", "after", "medium"):
        for f in sorted(d.glob(f"{kind}_*.json")) if d.exists() else []:
            doc = read(f.name)
            if doc:
                api.setdefault(doc.get("endpoint", f.stem), {})[kind] = doc
    kafka = [x for x in (read(f"kafka_scorers{k}.json") for k in (1, 2, 3)) if x]
    return {"spark": read("spark_scale.json"), "kafka": kafka, "api": api, "published": bool(kafka or api or read("spark_scale.json"))}


class AgentRequest(BaseModel):
    question: str = Field(min_length=2, max_length=500)
    use_llm: bool = True


@router.get("/agent/info", summary="Da Vinci AI: suggested questions and which engine would answer")
async def agent_info():
    prov = await resolve_agent_provider()
    return {"suggestions": davinci.SUGGESTIONS, "llm_available": prov["selected"] != "deterministic",
            "provider": prov["selected"], "model": prov["model"], "reason": prov.get("agent_note") or prov["reason"]}


@router.post("/agent", summary="Ask Da Vinci AI a question about the Big Data results (rules, optionally rewritten by an LLM)")
async def agent(req: AgentRequest):
    results, advanced = _load("results.json"), _load("advanced.json")
    extra = {"attacks_by_day": _load("attacks_by_day.json"), "cve": cve_lib.summary()[0]}
    question = davinci.clean_question(req.question)
    base = davinci.rules_answer(question, results, advanced, extra)
    # response procedures: retrieved when the question asks what to do, or when no Big Data rule matched
    hits: list[dict] = []
    if proc_lib.available() and (davinci.is_procedure_question(question) or base["matched"] is None):
        found = [h for h in proc_lib.search(question, 3) if h["score"] >= 3]
        hits = [x for x in (proc_lib.get(h["id"]) for h in found) if x]
        if hits:
            base = davinci.procedures_answer(hits)
            extra["procedures"] = hits
    # what is in the bucket (allow-listed datasets only)
    qn = question.lower()
    if any(w in qn for w in ("bucket", "fichier", "csv", "dataset", "jeu de donn", "stockage", "parquet", "files")):
        listing = []
        for root in ds_lib.roots():
            try:
                l = ds_lib.listing(root["prefix"])
                listing.append({"prefix": root["prefix"], "description": root["description"], "files": len(l.get("items", [])), "subfolders": len(l.get("prefixes", [])),
                                "bytes": sum(i["size"] for i in l.get("items", []))})
            except Exception:  # noqa: BLE001
                listing.append({"prefix": root["prefix"], "description": root["description"]})
        extra["bucket"] = listing
        if not davinci.is_procedure_question(question):
            hits = []
            extra.pop("procedures", None)
            base = {"answer": "Jeux de données exposés dans le bucket : " + " ; ".join(
                f"{x['prefix']} ({x.get('files', '?')} fichiers, {x.get('subfolders', 0)} sous-dossiers, {round(x.get('bytes', 0) / 1e9, 2)} Go) : {x['description']}" for x in listing)
                + ". Ils se parcourent dans la page API Console, onglet Datasets (CSV).", "sources": ["datasets"], "matched": "bucket"}
    # project documentation: fallback answer and extra context for the LLM
    doc_hits = [d for d in docs_index.search(question, 3) if d["score"] >= 2.5]
    if doc_hits:
        extra["docs"] = doc_hits
        generic = base["matched"] in (None, "pipeline", "limits")
        if generic and (base["matched"] is None or doc_hits[0]["score"] >= 8):
            base = davinci.docs_answer(doc_hits)
        else:
            base = {**base, "sources": list(dict.fromkeys(base.get("sources", []) + [f"{d['file']}#{d['section']}" for d in doc_hits[:2]]))}
    out = {**base, "engine": "rules", "model": "sfumato-davinci-rules-v1", "note": None}
    if not req.use_llm or (not results and not advanced and not hits and not extra.get("cve") and not extra.get("docs")):
        return out
    prov = await resolve_agent_provider()
    if prov["selected"] == "deterministic":
        out["note"] = f"LLM unavailable ({prov['reason']}): rules answer."
        return out
    if prov["selected"] == "ollama":   # small CPU model: short context, short system prompt
        user = "Question: " + question + "\n\n" + davinci.llm_context_compact(base, extra)
        system = (davinci.SYSTEM + " Be brief: at most 4 sentences.")
    else:
        user = ("Question: " + question + "\n\nDraft answer computed by rules (may be incomplete): " + base["answer"]
                + "\n\nDATA (JSON): " + davinci.llm_context(results, advanced, extra))
        system = davinci.SYSTEM
    try:
        async with llm_slot():
            data, model = await CALLERS[prov["selected"]](system, user, davinci.SCHEMA)
        text = str(data.get("answer", "")).strip()
        if text:
            return {**base, "answer": text, "engine": prov["selected"], "model": model, "note": None}
        out["note"] = "The LLM returned an empty answer: rules answer shown."
    except (LLMError, Exception) as e:  # noqa: BLE001 - never let the pop-up fail because of the LLM
        out["note"] = f"LLM error ({type(e).__name__}): rules answer shown."
    return out
