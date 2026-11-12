"""Turns normalised provider results into weighted CTI evidence and ML features.

An indicator that no provider knows produces *neutral* evidence — absence of intelligence is never
treated as proof of benignity.
"""
from __future__ import annotations

from collections import defaultdict

from app.cti.base import ProviderResult
from app.services.evidence import EvidenceBook


def correlate(results: list[ProviderResult], book: EvidenceBook) -> dict:
    by_ind: dict[tuple[str, str], list[ProviderResult]] = defaultdict(list)
    for r in results:
        by_ind[(r.indicator_type, r.indicator)].append(r)

    links: dict[int, str] = {}  # id(result) -> evidence id
    features = {"cti_malicious_providers": 0.0, "cti_suspicious_providers": 0.0, "cti_max_confidence": 0.0,
                "cti_allowlisted": 0.0, "cti_kev": 0.0, "cti_indicators_known": 0.0}
    mal_providers: set[str] = set()
    sus_providers: set[str] = set()

    for (itype, value), rs in by_ind.items():
        mal = [r for r in rs if r.verdict == "malicious"]
        sus = [r for r in rs if r.verdict == "suspicious"]
        allow = [r for r in rs if r.verdict == "allowlisted"]
        failed = [r for r in rs if r.status not in ("ok", "no_results")]
        origin = sorted({r.data_origin for r in rs})
        common = {"source": ", ".join(sorted({r.provider_name for r in (mal or sus or allow or rs)})),
                  "data": {"indicator": value, "indicator_type": itype, "data_origin": origin,
                           "providers": [{"provider": r.provider, "verdict": r.verdict, "status": r.status,
                                          "confidence": r.confidence, "summary": r.summary} for r in rs]}}
        ev = None
        if mal:
            confs = [r.confidence for r in mal if r.confidence is not None]
            max_conf = max(confs) if confs else 60
            fresh = [r.freshness_days for r in mal if r.freshness_days is not None]
            weight = min(45.0, 30 + 10 * (len(mal) - 1))
            if max_conf < 50:
                weight *= 0.7
            stale = bool(fresh) and min(fresh) > 180
            if stale:
                weight *= 0.6
            malware = sorted({m for r in mal for m in r.malware})
            mitre = sorted({t for r in rs for t in r.mitre})
            if itype == "cve":
                features["cti_kev"] = 1
                ev = book.add("cti", polarity="malicious", kind="known_exploited_vulnerability", weight=15,
                              title=f"{value} is a known exploited vulnerability",
                              description="; ".join(r.summary or "" for r in mal), mitre=["T1190"] + mitre, **common)
            else:
                ev = book.add("cti", polarity="malicious", kind="cti_malicious", weight=round(weight, 1),
                              title=f"{value} flagged malicious by {len(mal)} provider(s)",
                              description="; ".join(f"{r.provider_name}: {r.summary}" for r in mal)
                                          + (f". Associated malware: {', '.join(malware)}" if malware else "")
                                          + (" (intelligence is stale: last seen > 180 days)" if stale else ""),
                              mitre=mitre, **common)
            mal_providers.update(r.provider for r in mal)
            features["cti_max_confidence"] = max(features["cti_max_confidence"], max_conf / 100)
        elif sus:
            ev = book.add("cti", polarity="suspicious", kind="cti_suspicious",
                          weight=min(20.0, 12 + 4 * (len(sus) - 1)),
                          title=f"{value} reported as suspicious by {len(sus)} provider(s)",
                          description="; ".join(f"{r.provider_name}: {r.summary}" for r in sus),
                          mitre=sorted({t for r in rs for t in r.mitre}), **common)
            sus_providers.update(r.provider for r in sus)
            confs = [r.confidence for r in sus if r.confidence is not None]
            if confs:
                features["cti_max_confidence"] = max(features["cti_max_confidence"], max(confs) / 100 * 0.6)
        elif allow:
            features["cti_allowlisted"] = 1
            ev = book.add("cti", polarity="benign", benign_class="misidentification", kind="cti_allowlisted",
                          weight=10, title=f"{value} appears on provider allow/validation lists",
                          description="; ".join(f"{r.provider_name}: {r.summary}" for r in allow), **common)
        elif failed and len(failed) == len(rs):
            ev = book.add("cti", polarity="neutral", kind="cti_unavailable", weight=0,
                          title=f"No CTI answer for {value}",
                          description="All providers failed: " + "; ".join(f"{r.provider_name}: {r.error}" for r in failed),
                          **common)
        else:
            ev = book.add("cti", polarity="neutral", kind="cti_not_found", weight=0,
                          title=f"{value} unknown to queried providers",
                          description="No provider holds intelligence on this indicator. Unknown is not benign.",
                          **common)
        if mal or sus or allow:
            features["cti_indicators_known"] += 1
        for r in rs:
            links[id(r)] = ev.id

    features["cti_malicious_providers"] = float(len(mal_providers))
    features["cti_suspicious_providers"] = float(len(sus_providers))
    return {"features": features, "links": links,
            "malicious_indicators": sum(1 for rs in by_ind.values() if any(r.verdict == "malicious" for r in rs))}
