"""What the Da Vinci agent may read about the platform, beyond the Spark results: measured scalability, the open-set and PCAP experiments,
the machines and the incidents. Everything is read from the repository's result files or the database; nothing is invented here, and a
topic with no data is simply absent (the agent then says it has nothing on it).

`gather(question)` returns only the topics the question touches, so that the small CPU model (Qwen) is not flooded with context.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.config import get_settings

TOPIC_WORDS: dict[str, tuple[str, ...]] = {
    "scalability": ("scalab", "debit", "throughput", "kafka", "flink", "spark", "executor", "parallel", "stress", "charge", "load", "vcpu", "passage a l'echelle"),
    "open_set": ("open-set", "open set", "abstention", "abstain", "inconnu", "unknown", "escalad", "famille", "unseen", "zero-day", "triage"),
    "pcap": ("pcap", "zeek", "fenetre", "window", "par source", "per-source", "per source", "regle", "rule", "trafic brut", "raw traffic", "conn.log"),
    "architecture": ("vm", "machines", "architecture", "serveur", "server", "broker", "deploy", "gcp", "cloud", "qwen", "elk"),
    "incidents": ("incident", "investigation", "verdict", "alerte", "alert", "soar", "playbook", "gravite", "severity"),
}

ARCHITECTURE = [
    {"name": "sfumato", "target": "e2-standard-4", "role": "dashboard: Next.js front end, FastAPI back end, Caddy HTTPS with a team login; reads the Compute API for the Architecture page"},
    {"name": "sfumato-kafka-1", "target": "e2-standard-4", "role": "Kafka broker 1 and stress-test host: flow producer, scorer, CVE bridge, stress-test controller"},
    {"name": "sfumato-kafka-2", "target": "e2-standard-2", "role": "Kafka broker 2: scorer and CVE consumer"},
    {"name": "sfumato-kafka-3", "target": "e2-standard-2", "role": "Kafka broker 3: scorer"},
    {"name": "sfumato-flink", "target": "e2-standard-4", "role": "Flink with both jobs: flow analytics over network-flows and the per-source rule over conn-events"},
    {"name": "sfumato-qwen-clone", "target": "g2-standard-4 + NVIDIA L4 (Spot)", "role": "Ollama with Qwen on the L4 GPU (24 GB), used by Da Vinci; replaced the T4 VM when no T4 was available"},
    {"name": "sfumato-elk", "target": "e2-standard-2", "role": "Elasticsearch and Logstash for the logs (no Kibana)"},
    {"name": "sfumato-soar", "target": "e2-standard-4", "role": "external open-source SOAR (Shuffle): receives the investigation summary by webhook from the back end"},
    {"name": "sfumato-lg", "target": "e2-standard-8", "role": "worker: load generator for the stress tests and raw PCAP processing on demand"},
    {"name": "managed services", "target": "Cloud Storage, Dataproc Serverless (Spark), BigQuery, Cloud Run job + Scheduler", "role": "dataset and Parquet, batch jobs, SQL analytics, CVE feed every 12 hours"},
]


def architecture() -> dict:
    """Designed layout plus the real state of each machine when the Compute API can be read from here."""
    from app.services import gce
    snap = gce.snapshot()
    live = {v["name"]: v for v in snap.get("vms", [])} if snap.get("live") else {}
    rows = []
    for r in ARCHITECTURE:
        v = live.get(r["name"])
        rows.append({**r, **({"state": v["status"], "machine_type": v["machine_type"], "vcpus": v["vcpus"], "gpu": v["gpu"], "zone": v["zone"]} if v else {})})
    out: dict[str, Any] = {"live": bool(live), "machines": rows}
    if live:
        out["quotas"] = snap.get("quotas")
        out["running_vcpus"] = snap.get("running_vcpus")
        out["other_machines"] = [{"name": n, "state": v["status"], "machine_type": v["machine_type"]} for n, v in live.items() if n not in {r["name"] for r in ARCHITECTURE}]
    return out


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


def _root() -> Path:
    return Path(get_settings().repo_dir) / "ml"


def scalability() -> dict | None:
    d = _root() / "scale"
    spark = _read(d / "spark_scale.json")
    kafka = [x for x in (_read(d / f"kafka_scorers{k}.json") for k in (1, 2, 3)) if x]
    flink = [x for x in (_read(d / f"flink_source_p{p}.json") for p in (1, 2, 4)) if x]
    alerts = _read(d / "flink_source_alerts.json")
    if not (spark or kafka or flink):
        return None
    out: dict[str, Any] = {}
    if spark:
        out["spark_prep_seconds_by_executors"] = {str(r["executors"]): r.get("prep_seconds") for r in spark.get("runs", []) if r.get("prep_seconds")}
        out["spark_input_gb"] = spark.get("input_gb")
    if kafka:
        out["kafka_scorers_max_flows_per_s"] = {k["label"]: k.get("max_kept_up_per_s") for k in kafka}
    if flink:
        out["flink_per_source_by_parallelism"] = {str(f["parallelism"]): {"records": f["records_read"], "seconds": f["seconds"],
                                                  "avg_per_s": f["avg_records_per_s"], "peak_per_s": f["peak_records_per_s"]} for f in flink}
    if alerts:
        out["flink_rules_alert_quality"] = alerts
    return out


def open_set() -> dict | None:
    d = _read(_root() / "bigdata" / "open_set.json")
    return d if d else None


def pcap() -> dict | None:
    exp = _read(_root() / "bigdata" / "pcap_experiment.json")
    vol = _read(_root() / "bigdata" / "pcap_volume.json")
    if not (exp or vol):
        return None
    out: dict[str, Any] = dict(exp or {})
    if vol:
        out["volume"] = vol
    return out


def incidents() -> dict | None:
    try:
        from sqlalchemy import func, select  # imported here: the pure functions of this module must stay importable without the database stack

        from app.database.session import session_scope
        from app.models import Incident

        with session_scope() as s:
            total = s.scalar(select(func.count(Incident.id))) or 0
            if not total:
                return {"total": 0}
            by_sev = dict(s.execute(select(Incident.severity, func.count()).group_by(Incident.severity)).all())
            by_status = dict(s.execute(select(Incident.status, func.count()).group_by(Incident.status)).all())
            by_verdict = dict(s.execute(select(Incident.verdict, func.count()).where(Incident.verdict.is_not(None)).group_by(Incident.verdict)).all())
            review = s.scalar(select(func.count(Incident.id)).where(Incident.human_review_required.is_(True))) or 0
            return {"total": total, "by_severity": by_sev, "by_status": by_status, "by_verdict": by_verdict, "needing_human_review": review}
    except Exception:  # noqa: BLE001 - the agent must keep answering when the database is unavailable
        return None


LOADERS = {"scalability": scalability, "open_set": open_set, "pcap": pcap, "incidents": incidents, "architecture": architecture}


def topics_for(question: str) -> list[str]:
    q = question.lower()
    return [t for t, words in TOPIC_WORDS.items() if any(w in q for w in words)]


def gather(question: str) -> dict:
    """Only the topics the question touches; a topic that has no data is left out."""
    out = {}
    for t in topics_for(question):
        v = LOADERS[t]()
        if v:
            out[t] = v
    return out


def describe(ctx: dict) -> str | None:
    """Deterministic answer (French) for the topics that have a short factual summary; None when only the model can interpret the data."""
    parts = []
    s = ctx.get("scalability")
    if s:
        bits = []
        if s.get("spark_prep_seconds_by_executors"):
            bits.append("Spark, préparation de %s Go : " % s.get("spark_input_gb") + ", ".join(f"{k} exécuteurs {v} s" for k, v in s["spark_prep_seconds_by_executors"].items()))
        if s.get("kafka_scorers_max_flows_per_s"):
            bits.append("Kafka, débit maximal tenu : " + ", ".join(f"{k} : {v} flux/s" for k, v in s["kafka_scorers_max_flows_per_s"].items()))
        if s.get("flink_per_source_by_parallelism"):
            bits.append("Flink par source, parallélisme " + ", ".join(f"{k} : {v['avg_per_s']} enreg./s en moyenne" for k, v in s["flink_per_source_by_parallelism"].items()))
        parts.append("Scalabilité mesurée. " + " ; ".join(bits) + ".")
    p = (ctx.get("pcap") or {}).get("volume")
    if p:
        per_day = ", ".join(f"{d['day']} : {d['archive_bytes'] / 1e9:.1f} Go" + ("" if d.get("processed") else " (non traité)") for d in p["days"])
        parts.append(
            f"Trafic brut PCAP (CSE-CIC-IDS2018) : {p['total_archive_gb']} Go d'archives compressées sur {len(p['days'])} jours, dont {p['processed_archive_gb']} Go "
            f"traités ({p['processed_days']} jours) avec Zeek, réduits à {p['parquet_gb']} Go de journaux de connexions en Parquet. Par jour : {per_day}. "
            "Tailles des archives pcap.zip/pcap.rar, pas de la capture décompressée ; certains fichiers PCAP n'ont pas pu être lus par Zeek.")
    i = ctx.get("incidents")
    if i is not None:
        parts.append("Aucun incident enregistré." if not i.get("total") else
                     f"Incidents : {i['total']} au total, par gravité {i['by_severity']}, par statut {i['by_status']}, verdicts {i['by_verdict']}, {i['needing_human_review']} à revoir par un humain.")
    a = ctx.get("architecture")
    if a:
        head = "Machines (état réel lu sur Google Cloud)" if a.get("live") else "Machines (architecture prévue, état non lu)"
        items = []
        for v in a["machines"]:
            st = f" [{v['state'].lower()}, {v['machine_type']}{' + ' + ', '.join(v['gpu']) if v.get('gpu') else ''}]" if v.get("state") else f" [prévu : {v['target']}]"
            items.append(f"{v['name']}{st} : {v['role']}")
        extra = ""
        if a.get("live") and a.get("running_vcpus") is not None:
            extra = f" vCPU en marche : {a['running_vcpus']}."
        parts.append(head + " : " + " ; ".join(items) + "." + extra)
    return " ".join(parts) or None
