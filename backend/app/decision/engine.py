"""Transparent, deterministic verdict engine.

Inputs: the evidence book (behaviour, context, CTI, integrity), the ML result and the AI report.
The LLM never decides alone: its vote is capped at 5 points and only counts when a real LLM produced it.

Three numbers are kept separate:
* threat_score (0-100): how dangerous the observed activity looks, from weighted evidence;
* ML probabilities: the model's opinion, used as one bounded input;
* verdict confidence (0-100): how well the evidence supports the chosen verdict.

FALSE_POSITIVE vs LEGITIMATE_ACTIVITY
------------------------------------
* FALSE_POSITIVE — the detection misidentified the object/activity (approved signed software,
  sanctioned destination, provider allow-lists, documented noisy rule). Benign class "misidentification".
* LEGITIMATE_ACTIVITY — the detected behaviour really happened and is what the rule looks for, but it was
  authorised (verified change ticket, administrative account on a management host). Benign class
  "authorization".
When both kinds of benign evidence exist the larger total wins; ties go to LEGITIMATE_ACTIVITY because
the behaviour itself was confirmed.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from app.core.config import get_settings
from app.schemas.evidence import Evidence

ML_TO_VERDICT = {"true_positive": "TRUE_POSITIVE", "false_positive": "FALSE_POSITIVE",
                 "benign_positive": "LEGITIMATE_ACTIVITY"}


@dataclass
class DecisionConfig:
    tp_threshold: int = 55
    benign_max_threat: int = 25
    benign_min_points: float = 20
    contradiction_malicious: float = 40
    contradiction_benign: float = 35
    min_evidence_points: float = 20
    benign_offset: float = 0.5
    ml_weight: float = 15
    reference_weight: float = 10  # second-opinion model trained on real SOC labels (Microsoft GUIDE)
    ai_weight: float = 5
    criticality_multiplier: dict = field(default_factory=lambda: {"low": 0.9, "medium": 1.0, "high": 1.1,
                                                                  "critical": 1.2})


def load_config() -> DecisionConfig:
    path = Path(get_settings().config_dir) / "decision.json"
    if path.exists():
        return DecisionConfig(**json.loads(path.read_text(encoding="utf-8")))
    return DecisionConfig()


def evaluate(evidence: list[Evidence], ml: dict | None, ai: dict | None, criticality: str | None,
             completeness: float | None = None, cfg: DecisionConfig | None = None) -> dict:
    cfg = cfg or load_config()
    factors = {k: {"malicious": 0.0, "benign": 0.0, "evidence_ids": []}
               for k in ("cti", "behavior", "context", "integrity", "ml", "reference", "ai")}
    mal_points = auth_points = misid_points = 0.0
    for e in evidence:
        if e.category == "knowledge":  # general reference material, never evidence about this incident
            continue
        fac = factors[e.category if e.category in factors else "context"]
        if e.polarity in ("malicious", "suspicious"):
            mal_points += e.weight
            fac["malicious"] += e.weight
            fac["evidence_ids"].append(e.id)
        elif e.polarity == "benign":
            fac["benign"] += e.weight
            fac["evidence_ids"].append(e.id)
            if e.benign_class == "authorization":
                auth_points += e.weight
            else:
                misid_points += e.weight

    rationale: list[str] = []
    ml_vote = None
    if ml and ml.get("status") == "classified":
        p = ml["probabilities"]
        m_mal = cfg.ml_weight * p.get("true_positive", 0)
        m_fp = cfg.ml_weight * p.get("false_positive", 0)
        m_bp = cfg.ml_weight * p.get("benign_positive", 0)
        mal_points += m_mal
        misid_points += m_fp
        auth_points += m_bp
        factors["ml"].update(malicious=round(m_mal, 1), benign=round(m_fp + m_bp, 1))
        ml_vote = ML_TO_VERDICT[ml["label"]]
        rationale.append(f"ML ({ml['model_name']}) classified the alert as {ml['label']} "
                         f"(p={max(p.values()):.2f}); contribution capped at {cfg.ml_weight:g} points.")
    elif ml:
        rationale.append(f"ML abstained ({ml.get('reason')}); it does not influence the verdict.")

    ref_vote = None
    ref = (ml or {}).get("reference")
    if ref and ref.get("status") == "classified":
        pr = ref["probabilities"]
        r_mal = cfg.reference_weight * pr.get("true_positive", 0)
        r_fp = cfg.reference_weight * pr.get("false_positive", 0)
        r_bp = cfg.reference_weight * pr.get("benign_positive", 0)
        mal_points += r_mal
        misid_points += r_fp
        auth_points += r_bp
        factors["reference"].update(malicious=round(r_mal, 1), benign=round(r_fp + r_bp, 1))
        ref_vote = ML_TO_VERDICT[ref["label"]]
        rationale.append(f"Reference model (Microsoft GUIDE) classified the alert as {ref['label']} "
                         f"(p={max(pr.values()):.2f}); contribution capped at {cfg.reference_weight:g} points.")
    elif ref:
        rationale.append(f"Reference model (Microsoft GUIDE) abstained ({ref.get('reason')}).")

    ai_vote = None
    if ai and ai.get("mode") == "llm":
        ai_vote = ai.get("recommended_verdict")
        w = cfg.ai_weight
        if ai_vote == "TRUE_POSITIVE":
            mal_points += w
            factors["ai"]["malicious"] = w
        elif ai_vote == "FALSE_POSITIVE":
            misid_points += w
            factors["ai"]["benign"] = w
        elif ai_vote == "LEGITIMATE_ACTIVITY":
            auth_points += w
            factors["ai"]["benign"] = w
        rationale.append(f"AI investigator ({ai.get('provider')}) suggested {ai_vote}; vote capped at {w:g} points.")
    elif ai:
        rationale.append("AI report produced by the deterministic investigator; it carries no vote.")

    benign_points = auth_points + misid_points
    mult = cfg.criticality_multiplier.get(criticality or "medium", 1.0)
    threat = max(0, min(100, round(mal_points * mult - cfg.benign_offset * benign_points)))

    if mal_points >= cfg.contradiction_malicious and benign_points >= cfg.contradiction_benign:
        verdict, why = "INCONCLUSIVE", (f"Contradictory evidence: {mal_points:.0f} malicious points against "
                                         f"{benign_points:.0f} benign points.")
    elif threat >= cfg.tp_threshold:
        verdict, why = "TRUE_POSITIVE", f"Threat score {threat} ≥ {cfg.tp_threshold}."
    elif threat <= cfg.benign_max_threat and benign_points >= cfg.benign_min_points:
        if misid_points > auth_points:
            verdict, why = "FALSE_POSITIVE", (f"Low threat score ({threat}) and the benign evidence shows the "
                                              f"detection misidentified the activity ({misid_points:.0f} pts).")
        else:
            verdict, why = "LEGITIMATE_ACTIVITY", (f"Low threat score ({threat}) and the activity is covered by "
                                                   f"authorisation evidence ({auth_points:.0f} pts).")
    elif mal_points + benign_points < cfg.min_evidence_points:
        verdict, why = "INCONCLUSIVE", (f"Insufficient evidence: only {mal_points + benign_points:.0f} points of "
                                        f"evidence (minimum {cfg.min_evidence_points:g}).")
    else:
        verdict, why = "INCONCLUSIVE", (f"Threat score {threat} is between the benign ({cfg.benign_max_threat}) and "
                                        f"malicious ({cfg.tp_threshold}) thresholds.")
    rationale.insert(0, why)

    # Confidence in the verdict
    if verdict == "TRUE_POSITIVE":
        conf = 55 + min(35, threat - cfg.tp_threshold)
        if factors["cti"]["malicious"] > 0 and factors["behavior"]["malicious"] > 0:
            conf += 5
            rationale.append("CTI and behavioural evidence corroborate each other.")
    elif verdict in ("FALSE_POSITIVE", "LEGITIMATE_ACTIVITY"):
        conf = 55 + min(25, benign_points - cfg.benign_min_points) + (cfg.benign_max_threat - threat) / 2.5
    else:
        conf = 50
    if ml_vote and verdict != "INCONCLUSIVE":
        conf += 8 if ml_vote == verdict else -15
    if ai_vote and verdict != "INCONCLUSIVE":
        conf += 4 if ai_vote == verdict else -10
    if ref_vote and verdict != "INCONCLUSIVE":
        conf += 4 if ref_vote == verdict else -8
    if completeness is not None and completeness < 0.6:
        conf -= 10
        rationale.append(f"Evidence completeness is low ({completeness:.0%}).")
    conf = int(max(5, min(99, round(conf))))

    review_reasons = []
    if verdict == "INCONCLUSIVE":
        review_reasons.append("verdict is inconclusive")
    if verdict == "TRUE_POSITIVE" and criticality in ("high", "critical"):
        review_reasons.append(f"true positive on a {criticality}-criticality asset")
    if ml_vote and ml_vote != verdict:
        review_reasons.append(f"ML disagrees ({ml_vote})")
    if ai_vote and ai_vote != verdict:
        review_reasons.append(f"AI disagrees ({ai_vote})")
    if ref_vote and ref_vote != verdict and verdict != "INCONCLUSIVE":
        review_reasons.append(f"Reference model (GUIDE) disagrees ({ref_vote})")
    if any(e.kind == "prompt_injection" for e in evidence):
        review_reasons.append("prompt-injection content detected in the incident")
    if verdict in ("FALSE_POSITIVE", "LEGITIMATE_ACTIVITY") and conf < 60:
        review_reasons.append("benign verdict with limited confidence")

    for k in factors:
        factors[k]["malicious"] = round(factors[k]["malicious"], 1)
        factors[k]["benign"] = round(factors[k]["benign"], 1)
    return {
        "verdict": verdict, "threat_score": threat, "confidence": conf,
        "human_review_required": bool(review_reasons), "review_reasons": review_reasons,
        "points": {"malicious": round(mal_points, 1), "benign_authorization": round(auth_points, 1),
                   "benign_misidentification": round(misid_points, 1), "criticality_multiplier": mult},
        "factors": factors, "rationale": rationale, "ml_vote": ml_vote, "ref_vote": ref_vote, "ai_vote": ai_vote,
        "config": asdict(cfg),
    }
