"""Feature engineering shared by training (synthetic data generator) and online inference."""
from __future__ import annotations

import math

FEATURES: list[str] = [
    # alert-level
    "severity", "detector_confidence", "asset_criticality",
    # telemetry presence
    "has_process", "has_network", "has_auth", "has_file",
    # behaviour
    "office_parent_shell", "encoded_command", "download_cradle", "lolbin", "credential_access",
    "defense_evasion", "persistence", "lateral_movement", "ransomware", "nonstandard_port",
    "raw_ip_destination", "large_upload", "failed_logins_log", "geo_anomaly", "success_after_failures",
    "off_hours", "masquerading", "prompt_injection",
    # organisational context
    "verified_change", "unverified_change", "admin_context", "approved_software", "sanctioned_destination",
    "noisy_rule",
    # threat intelligence
    "cti_malicious_providers", "cti_suspicious_providers", "cti_max_confidence", "cti_allowlisted", "cti_kev",
    "public_indicators",
]

GROUPS = {
    "process": ["office_parent_shell", "encoded_command", "download_cradle", "lolbin", "credential_access",
                "defense_evasion", "persistence", "lateral_movement", "ransomware", "masquerading"],
    "network": ["nonstandard_port", "raw_ip_destination", "large_upload"],
    "auth": ["failed_logins_log", "geo_anomaly", "success_after_failures"],
}

SEVERITY = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CRITICALITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}
LABELS = ["true_positive", "false_positive", "benign_positive"]


def build_features(incident, behavior: dict, cti: dict, indicators: list[dict]) -> tuple[dict[str, float], dict]:
    bf = behavior["features"]
    tel = behavior["telemetry"]
    cf = cti.get("features", {})
    f = {
        "severity": float(SEVERITY[incident.severity.value]),
        "detector_confidence": (incident.metadata.confidence / 100) if incident.metadata.confidence is not None else 0.5,
        "asset_criticality": float(CRITICALITY.get(incident.asset.criticality.value, 1))
        if incident.asset and incident.asset.criticality else 1.0,
        "has_process": float(tel["process"]), "has_network": float(tel["network"]),
        "has_auth": float(tel["authentication"]), "has_file": float(tel["file"]),
        "public_indicators": float(min(10, sum(1 for i in indicators if i["shareable"]))),
    }
    for k in FEATURES:
        if k not in f:
            f[k] = float(bf.get(k, cf.get(k, 0.0)))
    # provider counts are capped to the range seen in training (more providers = same signal)
    f["cti_malicious_providers"] = min(f["cti_malicious_providers"], 3.0)
    f["cti_suspicious_providers"] = min(f["cti_suspicious_providers"], 2.0)
    f["failed_logins_log"] = min(f["failed_logins_log"], round(math.log1p(300), 3))
    # completeness: which evidence sources actually carried information for this alert
    sources = {
        "telemetry": any(tel[k] for k in ("process", "network", "authentication", "file")),
        "detector_confidence": incident.metadata.confidence is not None,
        "asset_context": bool(incident.asset and incident.asset.criticality),
        "cti_answers": cti.get("coverage", 0) > 0 and cti.get("planned_queries", 0) > 0,
        "user_context": tel.get("user", False),
    }
    meta = {"sources": sources, "completeness": round(sum(sources.values()) / len(sources), 2)}
    return f, meta


def vector(f: dict[str, float]) -> list[float]:
    return [float(f.get(k, 0.0)) for k in FEATURES]
