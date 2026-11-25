"""Da Vinci AI: question answering about the Big Data results.

Two layers, so the agent always answers:
  1. deterministic rules (keywords FR/EN -> an answer computed from results.json / advanced.json, with its sources);
  2. optionally an LLM (Gemini through the OpenAI-compatible provider, or any configured provider) that rewrites the answer
     in natural language from the SAME data. It receives aggregate statistics only (no incident, no IP, no credential)
     and is told to refuse anything the data does not support. If the LLM is unavailable, the rules answer is returned.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Callable

SUGGESTIONS = [
    "Combien de flux ont été traités ?",
    "Quelles attaques sont détectées même sans les avoir vues ?",
    "Pourquoi le test chronologique est-il si mauvais ?",
    "Le détecteur d'anomalies fonctionne-t-il ?",
    "Quelles sont les limites de l'étude ?",
    "Quelle VM fait quoi dans l'architecture ?",
    "Quel est le débit mesuré de Kafka et de Flink ?",
    "Combien d'incidents sont ouverts et lesquels sont critiques ?",
]


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s.lower())
    return "".join(c for c in s if not unicodedata.combining(c))


def _pct(x: float, d: int = 1) -> str:
    return f"{x * 100:.{d}f} %"


def _n(x: float) -> str:
    return f"{int(x):,}".replace(",", " ")


def _volume(r, a, d):
    if not r:
        return None, []
    return (f"Le jeu CSE-CIC-IDS2018 fait 6,89 Go. Spark a lu {_n(r['raw_rows'])} flux et en a gardé {_n(r['clean_rows'])} "
            f"({_n(r['dropped_rows'])} retirés, soit {_pct(r['dropped_rows'] / r['raw_rows'], 2)} : en-têtes répétés, Infinity/NaN, durées négatives). "
            f"Le traitement a pris {r['total_seconds'] // 60} min {r['total_seconds'] % 60} s."), ["results.json"]


def _classes(r, a, d):
    if not r:
        return None, []
    lc = sorted(r["eda"]["label_counts"].items(), key=lambda kv: -kv[1])
    tot = sum(v for _, v in lc)
    top = ", ".join(f"{k} ({_pct(v / tot)})" for k, v in lc[:4])
    rare = ", ".join(f"{k} ({_n(v)})" for k, v in lc[-3:])
    return (f"{len(lc) - 1} familles d'attaque pour {_n(tot)} flux. Les plus présentes : {top}. Les plus rares : {rare}. "
            f"Les classes sont très déséquilibrées : il faut lire AUC-PR, précision et rappel, pas l'exactitude."), ["results.json"]


def _schedule(r, a, d):
    rows = d.get("attacks_by_day", {}).get("rows") if d else None
    if not rows:
        return None, []
    by: dict[str, list[str]] = {}
    for x in rows:
        by.setdefault(x["day"], []).append(x["label"])
    txt = " ; ".join(f"{day[5:]} : {', '.join(labs)}" for day, labs in sorted(by.items()))
    return ("Les attaques sont planifiées par jour (laboratoire) : " + txt + ". Conséquence : un test chronologique place des familles "
            "entières hors de l'entraînement."), ["attacks_by_day.json"]


def _random_split(r, a, d):
    m = (r or {}).get("ml", {}).get("random_split")
    if not m:
        return None, []
    return (f"Random Forest, découpage aléatoire ({_n(m['test_rows'])} flux de test) : AUC-ROC {m['auc_roc']:.3f}, AUC-PR {m['auc_pr']:.3f}, "
            f"précision {m['precision']:.3f}, rappel {m['recall']:.3f}, F1 {m['f1']:.3f}. Ce score est optimiste : toutes les familles sont "
            f"dans l'entraînement."), ["results.json"]


def _holdout(r, a, d):
    m = (r or {}).get("ml", {}).get("time_holdout")
    if not m:
        return None, []
    return (f"Test chronologique (entraînement avant le {m['cutoff_day']}, {_n(m['test_rows'])} flux de test) : AUC-PR {m['auc_pr']:.3f}, "
            f"rappel {m['recall']:.4f} ({_n(m['confusion']['tp'])} attaques détectées, {_n(m['confusion']['fn'])} manquées). "
            f"Cause : l'infiltration et le botnet n'apparaissent que dans les jours de test. Le modèle ne détecte pas ce qu'il n'a jamais vu."), ["results.json"]


def _unseen(r, a, d):
    if not a:
        return None, []
    an = {f["family"]: f["recall"] for f in a["anomaly"]["families"]}
    fam = sorted(a["supervised"]["families"], key=lambda f: -f["recall_unseen"])
    good = ", ".join(f"{f['family']} {f['recall_unseen']:.2f}" for f in fam if f["recall_unseen"] >= 0.9)
    bad = ", ".join(f"{f['family']} {f['recall_unseen']:.3f}" for f in fam if f["recall_unseen"] < 0.1)
    return (f"Rappel quand la famille est inconnue du modèle supervisé (faux positifs ≈ {_pct(a['supervised']['fpr_seen_model'])}) : "
            f"bien détectées : {good or 'aucune'}. Quasi invisibles : {bad or 'aucune'}. Les variantes proches d'une famille connue passent, "
            f"les comportements nouveaux non."), ["advanced.json"]


def _anomaly(r, a, d):
    if not a:
        return None, []
    fam = sorted(a["anomaly"]["families"], key=lambda f: -f["recall"])
    hit = [f for f in fam if f["recall"] >= 0.1]
    miss = [f for f in fam if f["recall"] < 0.1]
    hit_txt = ", ".join(f"{f['family']} {f['recall']:.2f} ({_n(f['test_flows'])} flux de test)" for f in hit) or "aucune"
    return (f"Très peu. Le détecteur KMeans (k = {a['anomaly']['k']}, appris sur le trafic normal, {_pct(a['anomaly']['fpr'], 2)} de faux positifs) "
            f"ne repère que : {hit_txt}. Rappel proche de 0 sur les {len(miss)} autres familles, dont HOIC, Hulk, Bot, SSH et l'infiltration. "
            f"LOIC-UDP est un comportement extrême sur peu de flux. Causes possibles, non testées : variables à queue lourde, trafic normal trop "
            f"varié pour 20 centres, attaques dans l'enveloppe normale."), ["advanced.json"]


def _cve(r, a, d):
    c = (d or {}).get("cve")
    if not c:
        return "Le flux de vulnérabilités n'a pas encore été publié : lance l'ingestion (bigdata/cve_ingest.py).", []
    k, n, e = c["kev"], c["nvd"], c["epss"]
    sev = n["by_severity"]
    last = ", ".join(f"{v['id']} ({v['vendor']} {v['product']}, ajouté le {v['added']})" for v in k["recent"][:3])
    top = e["top"][0] if e["top"] else None
    txt = (f"Sur les {c['window_days']} derniers jours : {_n(n['published_in_window'])} CVE publiées dans le NVD "
           f"(critiques {sev.get('CRITICAL', 0)}, hautes {sev.get('HIGH', 0)}, moyennes {sev.get('MEDIUM', 0)}, sans score {sev.get('UNSCORED', 0)} : "
           f"le score est souvent absent les premiers jours). Le catalogue CISA KEV compte {_n(k['total'])} vulnérabilités exploitées, "
           f"dont {k['added_in_window']} ajoutées sur la période et {_n(k['ransomware_known'])} liées à des rançongiciels. Dernières entrées KEV : {last}.")
    if top:
        txt += f" Plus forte probabilité d'exploitation (EPSS) parmi les CVE récentes : {top['id']} ({top['epss']['epss']:.2f})."
    return txt + " Priorité : une CVE présente dans le KEV passe avant le score CVSS (voir la procédure PROC-128).", ["cves/summary"]


def _cost(r, a, d):
    return ("Le coût du run n'a pas été relevé : il faut le lire dans Billing (console GCP). Je ne donne aucun montant. "
            "Les calculs Spark sont facturés à l'usage ; restent un peu de stockage (bucket, BigQuery) et le disque de la VM."), ["docs/BIGDATA_PROJECT.md"]


def _multiclass(r, a, d):
    if not a:
        return None, []
    m = a["multiclass"]
    weak = sorted(m["per_class"], key=lambda c: c["f1"])[:4]
    return (f"Classification de la famille : exactitude {m['accuracy']:.3f}, F1 macro {m['macro_f1']:.3f}. Les classes les plus faibles : "
            + ", ".join(f"{c['label']} (F1 {c['f1']:.2f}, support {_n(c['support'])})" for c in weak)
            + ". Les très bonnes familles ont un comportement réseau très net (DoS, SSH, botnet)."), ["advanced.json"]


def _features(r, a, d):
    fi = (r or {}).get("ml", {}).get("feature_importances")
    if not fi:
        return None, []
    return ("Variables les plus importantes : " + ", ".join(f"{x['feature']} ({x['importance']:.3f})" for x in fi[:6])
            + ". Attention : le port de destination peut servir de raccourci."), ["results.json"]


def _limits(r, a, d):
    return ("Limites : (1) heures 1-12 seulement dans les sources, probablement une horloge de 12 h, donc l'analyse par heure est indicative ; "
            "(2) jeu de laboratoire, attaques planifiées par jour ; (3) le détecteur d'anomalies n'a pas fonctionné ; (4) le modèle ne généralise pas "
            "aux familles inconnues ; (5) les chiffres ML avancés viennent d'échantillons plafonnés ; (6) pas de temps réel ; "
            "(7) le coût du run n'a pas été relevé."), ["docs/BIGDATA_PROJECT.md"]


def _pipeline(r, a, d):
    return ("Pipeline : ingestion des 10 CSV vers Cloud Storage, nettoyage Spark sur Dataproc Serverless (union de deux formats de colonnes, "
            "Parquet partitionné par jour), analyses SQL dans BigQuery, Random Forest MLlib, puis cette page. Spark parce que le plus gros "
            "fichier fait 4 Go et que le traitement est borné (batch) ; Parquet pour lire peu de colonnes ; BigQuery pour le SQL analytique."), ["docs/BIGDATA_PROJECT.md"]


RULES: list[tuple[tuple[str, ...], Callable]] = [
    (("cve", "kev", "vulnerabilite", "epss", "cvss", "nvd", "faille", "vulnerab"), _cve),
    (("cout", "coute", "prix", "factur", "cost", "budget", "billing", "euro", "dollar"), _cost),
    (("combien", "volume", "flux", "lignes", "taille", "rows", "how many", "nettoy", "qualite", "dropped", "clean"), _volume),
    (("chronolog", "holdout", "hold-out", "temporel", "time split", "pourquoi", "mauvais"), _holdout),
    (("inconnu", "unseen", "jamais vu", "nouvelle", "zero-day", "generalis", "sans les avoir"), _unseen),
    (("anomal", "kmeans", "non supervis", "unsupervised"), _anomaly),
    (("multiclass", "famille d'attaque", "par classe", "f1 macro", "classification"), _multiclass),
    (("aleatoire", "random split", "performance", "precision", "rappel", "recall", "auc", "score", "modele"), _random_split),
    (("jour", "planif", "schedule", "quand", "calendrier", "day"), _schedule),
    (("classe", "desequilibre", "repartition", "benign", "famille", "balance", "attaques"), _classes),
    (("variable", "feature", "importance"), _features),
    (("limite", "biais", "caveat", "limit", "fiable", "heure"), _limits),
    (("pipeline", "outil", "pourquoi spark", "architecture", "comment", "bigquery", "parquet"), _pipeline),
]


def rules_answer(question: str, results: dict | None, advanced: dict | None, extra: dict | None = None) -> dict:
    q = _norm(question)
    extra = extra or {}
    scored = []
    for keys, fn in RULES:
        s = sum(1 for k in keys if _norm(k) in q)
        if s:
            scored.append((s, fn))
    for _, fn in sorted(scored, key=lambda t: -t[0]):
        text, sources = fn(results, advanced, extra)
        if text:
            return {"answer": text, "sources": sources, "matched": fn.__name__.strip("_")}
    if not results and not advanced:
        return {"answer": "Les résultats Spark ne sont pas encore publiés : je n'ai aucune donnée à interroger.", "sources": [], "matched": None}
    return {"answer": "Je peux répondre sur : le volume et la qualité des données, la répartition des classes, le calendrier des attaques, "
                      "les performances du modèle (aléatoire et chronologique), les familles inconnues, le détecteur d'anomalies, "
                      "la classification par famille, les variables importantes, les limites et le pipeline.",
            "sources": [], "matched": None}


SYSTEM = (
    "You are Da Vinci AI, the data-analysis assistant of the Sfumato SOC project. Answer ONLY from the JSON data provided. "
    "If the data does not contain the answer, say so plainly; never invent a number, a dataset or a result. "
    "Reply in the language of the question, in at most 6 sentences, quoting figures exactly as given. "
    "Mention a limitation when the data carries one (sampled figures, failed experiments). "
    "Response procedures in the data are generated drafts that were not validated by a professional: say so when you use them. Return JSON: {\"answer\": string}."
)
SCHEMA = {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}


PROC_WORDS = ("procedure", "runbook", "que faire", "comment reagir", "comment repondre", "reponse a incident", "playbook", "mitigat",
              "contenir", "containment", "contain", "eradic", "remediation", "how to respond", "how do i respond", "what to do", "t1", "proc-")


def is_procedure_question(question: str) -> bool:
    q = _norm(question)
    return any(w in q for w in PROC_WORDS)


def procedures_answer(hits: list[dict]) -> dict:
    """hits: full procedures (id, title, severity, triage, contain, eradicate, recover...). Deterministic summary of the best match."""
    top = hits[0]
    others = ", ".join(f"{h['id']} {h['title']}" for h in hits[1:])
    text = (f"Procédure la plus proche : {top['id']} - {top['title']} (gravité {top['severity']}, tactique {top['tactic']}). "
            f"Triage : {' ; '.join(top['triage'][:3])}. Confinement : {' ; '.join(top['contain'][:2])}. "
            f"Éradication : {' ; '.join(top['eradicate'][:2])}." + (f" Voir aussi : {others}." if others else "")
            + " Rappel : ces procédures sont des brouillons générés, non validés par un professionnel.")
    return {"answer": text, "sources": [f"procedures/{h['id']}" for h in hits], "matched": "procedures"}


def docs_answer(hits: list[dict]) -> dict:
    top = hits[0]
    snippet = " ".join(top["text"].split())[:420]
    return {"answer": f"D'après la documentation du projet ({top['file']}, section « {top['section']} ») : {snippet}",
            "sources": [f"{h['file']}#{h['section']}" for h in hits], "matched": "docs"}


def llm_context_compact(base: dict, extra: dict | None) -> str:
    """Short context for a small CPU model: the rules draft (which already carries the exact figures) plus at most two short excerpts.
    A 7B model reads a few hundred tokens per ten seconds on 4 vCPUs, so the full JSON used with Gemini would make it unusable."""
    parts = [f"Verified draft answer (figures are exact): {base['answer']}"]
    ex = extra or {}
    for d in (ex.get("docs") or [])[:2]:
        parts.append(f"Documentation excerpt [{d['file']}#{d['section']}]: {' '.join(d['text'].split())[:650]}")
    for pr in (ex.get("procedures") or [])[:1]:
        parts.append(f"Procedure {pr['id']} {pr['title']} (draft, not validated). Triage: {'; '.join(pr['triage'][:3])}. Containment: {'; '.join(pr['contain'][:2])}.")
    if ex.get("platform"):
        parts.append("Platform data (JSON, exact): " + json.dumps({k: v for k, v in ex["platform"].items() if k not in ("architecture",)}, ensure_ascii=False, default=str)[:1800])
    if ex.get("bucket"):
        parts.append("Bucket datasets: " + "; ".join(f"{b['prefix']} ({b.get('files', '?')} files)" for b in ex["bucket"]))
    return "\n".join(parts)[:3200]


def llm_context(results: dict | None, advanced: dict | None, extra: dict | None) -> str:
    ctx: dict[str, Any] = {}
    if extra and extra.get("cve"):
        c = extra["cve"]
        ctx["cve_feed"] = {"window_days": c["window_days"], "kev": {k: v for k, v in c["kev"].items() if k != "recent"} | {"recent": c["kev"]["recent"][:15]},
                           "nvd": {k: v for k, v in c["nvd"].items() if k not in ("top_cvss", "per_day")}, "epss_top": c["epss"]["top"][:10],
                           "limitations": c["limitations"]}
    if extra and extra.get("docs"):
        ctx["project_documentation_excerpts"] = [{"source": f"{d['file']}#{d['section']}", "text": d["text"]} for d in extra["docs"]]
    if extra and extra.get("bucket"):
        ctx["bucket_datasets"] = extra["bucket"]
    if extra and extra.get("platform"):
        ctx["platform"] = extra["platform"]
    if extra and extra.get("procedures"):
        ctx["procedures_draft_not_validated"] = extra["procedures"]
    if results:
        ctx["results"] = {k: v for k, v in results.items() if k != "json"}
    if advanced:
        ctx["advanced"] = advanced
    if extra:
        ctx["attacks_by_day"] = extra.get("attacks_by_day", {}).get("rows")
    return json.dumps(ctx, ensure_ascii=False, default=str)[:60000]


def clean_question(q: str) -> str:
    return re.sub(r"\s+", " ", q).strip()[:500]
