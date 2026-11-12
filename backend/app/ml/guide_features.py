"""Incident-level features in the vocabulary of the Microsoft GUIDE dataset.

GUIDE (Microsoft Security Incident Prediction, Kaggle, CDLA-Permissive-2.0) holds ~1M real SOC incidents graded
TruePositive / BenignPositive / FalsePositive by customer analysts. Most of its columns are anonymised
identifiers (DetectorId, AlertTitle, DeviceId, …) that no other system can reproduce, so the model only uses what
is *portable*: the alert category, the MITRE ATT&CK techniques, the types of entities involved and the time of day.
Everything is matched through a vocabulary learnt from the data and normalised names, so "initial-access" in a
Sfumato alert matches "InitialAccess" in GUIDE.

Standalone (standard library + numpy): this exact file is used for training (Kaggle notebook) and inference
(Sfumato backend), so training and serving cannot drift apart.
"""
from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Iterable

import numpy as np

LABELS = ["true_positive", "false_positive", "benign_positive"]
GRADE_MAP = {"truepositive": "true_positive", "falsepositive": "false_positive", "benignpositive": "benign_positive"}
MAX_TECHNIQUES = 8


def norm_key(value) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def split_techniques(value) -> list[str]:
    """'T1059.001;T1566' -> ['T1059.001', 'T1059', 'T1566'] (sub-techniques also count as their parent)."""
    out: list[str] = []
    for t in re.findall(r"T\d{4}(?:\.\d{3})?", str(value or "").upper()):
        out.append(t)
        base = t.split(".")[0]
        if base != t:
            out.append(base)
    return out


def build_vocab(categories: dict[str, int], techniques: dict[str, int], entities: dict[str, int],
                max_categories: int = 60, max_techniques: int = 150, max_entities: int = 40) -> dict:
    def top(counter: dict[str, int], n: int, keyfn=lambda x: x) -> list[str]:
        seen, out = set(), []
        for k, _ in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
            nk = keyfn(k)
            if nk and nk not in seen:
                seen.add(nk)
                out.append(nk)
            if len(out) >= n:
                break
        return out

    return {"categories": top(categories, max_categories, norm_key),
            "techniques": top(techniques, max_techniques, lambda t: t.upper()),
            "entities": top(entities, max_entities, norm_key)}


def feature_names(vocab: dict) -> list[str]:
    return ([f"cat:{c}" for c in vocab["categories"]] + [f"tech:{t}" for t in vocab["techniques"]]
            + [f"ent:{e}" for e in vocab["entities"]]
            + ["n_categories", "n_techniques", "n_entity_types", "no_category", "no_technique",
               "hour_sin", "hour_cos", "weekend"])


def _parse_ts(ts) -> datetime | None:
    if ts is None or ts == "":
        return None
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def featurize(vocab: dict, categories: Iterable[str], techniques: Iterable[str], entities: Iterable[str],
              timestamp=None) -> tuple[np.ndarray, dict]:
    """Returns (feature vector, coverage). coverage tells how many of the provided signals the vocabulary knows."""
    cats = {norm_key(c) for c in categories if norm_key(c)}
    techs = {t for raw in techniques for t in split_techniques(raw)}
    ents = {norm_key(e) for e in entities if norm_key(e)}
    ci = {c: i for i, c in enumerate(vocab["categories"])}
    ti = {t: i for i, t in enumerate(vocab["techniques"])}
    ei = {e: i for i, e in enumerate(vocab["entities"])}
    nc, nt, ne = len(ci), len(ti), len(ei)
    x = np.zeros(nc + nt + ne + 8, dtype=np.float32)
    for c in cats:
        if c in ci:
            x[ci[c]] = 1
    for t in techs:
        if t in ti:
            x[nc + ti[t]] = 1
    for e in ents:
        if e in ei:
            x[nc + nt + ei[e]] = 1
    base_techs = {t for t in techs if "." not in t}
    o = nc + nt + ne
    x[o] = len(cats)
    x[o + 1] = min(len(base_techs), MAX_TECHNIQUES)
    x[o + 2] = len(ents)
    x[o + 3] = 0 if cats else 1
    x[o + 4] = 0 if techs else 1
    dt = _parse_ts(timestamp)
    if dt is not None:
        x[o + 5] = math.sin(2 * math.pi * dt.hour / 24)
        x[o + 6] = math.cos(2 * math.pi * dt.hour / 24)
        x[o + 7] = 1 if dt.weekday() >= 5 else 0
    matched = {"categories": [c for c in cats if c in ci], "techniques": [t for t in techs if t in ti],
               "entities": [e for e in ents if e in ei]}
    provided = {"categories": len(cats), "techniques": len(techs), "entities": len(ents)}
    present = [k for k, n in provided.items() if n]
    coverage = (sum(1 for k in present if matched[k]) / len(present)) if present else 0.0
    return x, {"coverage": round(coverage, 3), "provided": provided, "matched": {k: sorted(v) for k, v in matched.items()}}
