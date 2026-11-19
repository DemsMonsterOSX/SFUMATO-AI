"""Response-procedure library: lexical (BM25) search over ml/procedures/index.json.

Pure Python, no model download, works offline on the 1 GB VM. Procedures are DRAFT material generated for a course project
(status field): they are reference guidance for analysts, never evidence about an incident, and cannot change a verdict.
"""
from __future__ import annotations

import json
import math
import re
import threading
import unicodedata
from collections import Counter
from pathlib import Path

from app.core.config import get_settings

_STOP = set("the a an of to in on for and or with is are be by at as it this that from not no les le la des du de un une et ou pour dans sur par est sont que qui au aux ce ces".split())
# FR -> EN hints so French questions reach the English library
_FR_EN = {"hameconnage": "phishing", "hameconnage": "phishing", "rancongiciel": "ransomware", "rancon": "ransomware", "force": "bruteforce brute force",
          "deni": "denial", "service": "service", "injection": "injection", "motdepasse": "password", "mot": "password", "passe": "password",
          "identifiants": "credentials", "fuite": "leak exposure", "cle": "key", "compte": "account", "botnet": "botnet bot", "infiltration": "infiltration",
          "balayage": "scan", "analyse": "scan", "latéral": "lateral", "lateral": "lateral", "exfiltration": "exfiltration", "vol": "theft", "donnees": "data",
          "vulnerabilite": "vulnerability cve", "faille": "vulnerability", "journal": "logs", "journaux": "logs", "persistance": "persistence",
          "privileges": "privilege", "elevation": "escalation", "confinement": "containment", "isoler": "isolate containment", "preuves": "evidence",
          "faux": "false", "positif": "positive", "attaque": "attack", "inconnue": "unseen", "apprentissage": "machine learning model drift",
          "anomalies": "anomaly detector", "anomalie": "anomaly", "detecteur": "detector", "echoue": "fail failed", "echec": "failure", "tombe": "fails failure",
          "panne": "failure fault tolerance", "debit": "rate limit throughput", "limite": "limit", "limites": "limits", "ingerees": "ingestion", "ingestion": "ingestion ingest",
          "requetes": "requests", "requete": "request", "deploiement": "deploy deployment", "deployer": "deploy", "cout": "cost", "couts": "cost budget",
          "flux": "flows streaming stream", "fonctionne": "works architecture", "architecture": "architecture design", "journaux": "logs", "surcharge": "overload stress",
          "tolerance": "fault tolerance", "reseau": "network", "donnees": "data dataset", "modele": "model", "perf": "performance", "performances": "performance throughput"}
_lock = threading.Lock()
_cache: dict = {"mtime": None, "docs": None, "idx": None}


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s.lower())
    return "".join(c for c in s if not unicodedata.combining(c))


def tokens(s: str) -> list[str]:
    out = []
    for t in re.findall(r"[a-z0-9][a-z0-9._-]*", _norm(s)):
        if t in _STOP or len(t) < 2:
            continue
        out.append(t)
        out.extend(x for x in re.split(r"[._-]", t) if len(x) > 1 and x != t)
        if t in _FR_EN:
            out.extend(_FR_EN[t].split())
    return out


def _path() -> Path:
    return Path(get_settings().repo_dir) / "ml" / "procedures" / "index.json"


def _load():
    p = _path()
    if not p.exists():
        return None, None
    m = p.stat().st_mtime
    with _lock:
        if _cache["mtime"] == m:
            return _cache["docs"], _cache["idx"]
        docs = json.loads(p.read_text(encoding="utf-8"))
        tf = [Counter(tokens(d["text"] + " " + d["id"] + " " + d["title"] * 2)) for d in docs]
        df: Counter = Counter()
        for c in tf:
            df.update(c.keys())
        n = len(docs)
        idx = {"tf": tf, "len": [sum(c.values()) for c in tf], "df": df, "n": n, "avg": sum(sum(c.values()) for c in tf) / max(n, 1)}
        _cache.update(mtime=m, docs=docs, idx=idx)
        return docs, idx


def available() -> bool:
    return _path().exists()


def summary(d: dict) -> dict:
    return {k: d[k] for k in ("id", "title", "tactic", "techniques", "severity", "tags", "dataset_families", "status")}


def list_all() -> list[dict]:
    docs, _ = _load()
    return [summary(d) for d in docs or []]


def get(pid: str) -> dict | None:
    docs, _ = _load()
    for d in docs or []:
        if d["id"].lower() == pid.lower():
            return {k: v for k, v in d.items() if k != "text"}
    return None


def search(query: str, limit: int = 5, tactic: str | None = None, severity: str | None = None) -> list[dict]:
    docs, idx = _load()
    if not docs:
        return []
    q = tokens(query)
    # direct hits: procedure id, ATT&CK technique id, dataset family name
    ql = query.lower()
    out: list[tuple[float, dict]] = []
    for i, d in enumerate(docs):
        if tactic and d["tactic"].lower() != tactic.lower():
            continue
        if severity and d["severity"].lower() != severity.lower():
            continue
        s = 0.0
        k1, b = 1.5, 0.75
        for t in set(q):
            f = idx["tf"][i].get(t, 0)
            if not f:
                continue
            idf = math.log(1 + (idx["n"] - idx["df"][t] + 0.5) / (idx["df"][t] + 0.5))
            s += idf * f * (k1 + 1) / (f + k1 * (1 - b + b * idx["len"][i] / idx["avg"]))
        if d["id"].lower() in ql:
            s += 50
        if any(t.lower() in ql for t in d["techniques"]):
            s += 8
        if any(_norm(f) in _norm(query) for f in d.get("dataset_families", [])):
            s += 10
        if s > 0:
            out.append((s, d))
    out.sort(key=lambda t: -t[0])
    return [{**summary(d), "score": round(s, 3)} for s, d in out[:limit]]
