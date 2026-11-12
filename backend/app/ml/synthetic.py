"""Explicitly labelled SYNTHETIC SOC alert triage dataset generator.

Why synthetic? The most relevant public dataset, Microsoft GUIDE (CDLA-Permissive-2.0, Kaggle), has the
right label taxonomy (TruePositive / BenignPositive / FalsePositive) but its features are anonymised IDs
that cannot be derived from a raw alert in our JSON format, and it requires a Kaggle account to download.
Network intrusion datasets (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) label *flows*, not SOC alert
triage outcomes, so they do not match the classification objective.

This generator therefore samples alerts from documented analyst archetypes with overlapping feature
distributions, feature noise, missing telemetry and label noise. Metrics measured on it describe how
well the model recovers these archetypes — they are NOT a claim about real-world SOC performance.
See docs/MACHINE_LEARNING.md.
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd

from app.ml.features import FEATURES, GROUPS

DATASET_NAME = "sfumato-synthetic-soc-triage"
DATASET_VERSION = "1.0"

# Per archetype: telemetry presence, Bernoulli probabilities of binary features, and continuous settings.
ARCHETYPES: dict[str, list[dict]] = {
    "true_positive": [
        {"name": "macro_dropper", "w": 0.24, "tel": {"has_process": 1, "has_network": 0.6},
         "p": {"office_parent_shell": .85, "encoded_command": .6, "download_cradle": .7, "defense_evasion": .45,
               "persistence": .2, "nonstandard_port": .15, "raw_ip_destination": .3, "off_hours": .3,
               "unverified_change": .03, "admin_context": .05},
         "cti_mal": .55, "cti_sus": .25, "sev": (2, 4)},
        {"name": "c2_beacon", "w": 0.2, "tel": {"has_network": 1, "has_process": 0.6},
         "p": {"nonstandard_port": .5, "raw_ip_destination": .5, "large_upload": .2, "lolbin": .3, "encoded_command": .25,
               "off_hours": .4, "sanctioned_destination": .03},
         "cti_mal": .75, "cti_sus": .35, "sev": (2, 4)},
        {"name": "brute_force_success", "w": 0.18, "tel": {"has_auth": 1},
         "p": {"success_after_failures": .8, "geo_anomaly": .6, "off_hours": .45, "admin_context": .08},
         "fails": (12, 300), "cti_mal": .3, "cti_sus": .35, "sev": (2, 3)},
        {"name": "credential_dump", "w": 0.14, "tel": {"has_process": 1},
         "p": {"credential_access": .85, "defense_evasion": .4, "lolbin": .3, "masquerading": .2, "admin_context": .1,
               "prompt_injection": .05},
         "cti_mal": .2, "cti_sus": .2, "sev": (3, 4)},
        {"name": "lateral_ransom", "w": 0.12, "tel": {"has_process": 1, "has_network": 0.4},
         "p": {"lateral_movement": .7, "ransomware": .45, "persistence": .3, "unverified_change": .1, "admin_context": .1},
         "cti_mal": .25, "cti_sus": .2, "sev": (3, 4)},
        {"name": "masquerade_malware", "w": 0.12, "tel": {"has_process": 1, "has_file": 0.7},
         "p": {"masquerading": .8, "persistence": .4, "approved_software": .03},
         "cti_mal": .45, "cti_sus": .2, "sev": (2, 4)},
    ],
    "false_positive": [
        {"name": "approved_software", "w": 0.3, "tel": {"has_process": 0.8, "has_file": 0.5},
         "p": {"approved_software": .85, "noisy_rule": .35, "lolbin": .08, "encoded_command": .04},
         "cti_mal": .02, "cti_sus": .05, "cti_allow": .2, "sev": (0, 3)},
        {"name": "sanctioned_update", "w": 0.22, "tel": {"has_network": 1, "has_process": 0.5},
         "p": {"sanctioned_destination": .85, "nonstandard_port": .05, "raw_ip_destination": .08, "approved_software": .3},
         "cti_mal": .02, "cti_sus": .08, "cti_allow": .45, "sev": (1, 3)},
        {"name": "noisy_rule", "w": 0.2, "tel": {"has_process": 1},
         "p": {"noisy_rule": .85, "approved_software": .4, "off_hours": .2},
         "cti_mal": .01, "cti_sus": .03, "sev": (0, 2)},
        {"name": "user_typo", "w": 0.14, "tel": {"has_auth": 1},
         "p": {"success_after_failures": .08, "geo_anomaly": .05, "off_hours": .25},
         "fails": (1, 14), "cti_mal": .02, "cti_sus": .05, "sev": (1, 2)},
        {"name": "shared_infrastructure", "w": 0.14, "tel": {"has_network": 1},
         "p": {"sanctioned_destination": .3, "raw_ip_destination": .2},
         "cti_mal": .12, "cti_mal_conf": (0.2, 0.45), "cti_sus": .5, "cti_allow": .3, "sev": (1, 3)},
    ],
    "benign_positive": [
        {"name": "admin_scripting", "w": 0.3, "tel": {"has_process": 1},
         "p": {"admin_context": .8, "encoded_command": .35, "download_cradle": .25, "defense_evasion": .15,
               "verified_change": .3, "unverified_change": .08, "off_hours": .25},
         "cti_mal": .02, "cti_sus": .05, "sev": (1, 3)},
        {"name": "patch_deployment", "w": 0.25, "tel": {"has_process": 1, "has_network": 0.7},
         "p": {"verified_change": .8, "admin_context": .6, "lateral_movement": .3, "download_cradle": .3,
               "sanctioned_destination": .4, "persistence": .15},
         "cti_mal": .01, "cti_sus": .03, "cti_allow": .3, "sev": (1, 3)},
        {"name": "admin_remote_execution", "w": 0.25, "tel": {"has_process": 1, "has_network": 0.5},
         "p": {"lateral_movement": .6, "admin_context": .75, "verified_change": .25, "off_hours": .3},
         "cti_mal": .01, "cti_sus": .03, "sev": (1, 3)},
        {"name": "authorised_scanning", "w": 0.2, "tel": {"has_network": 1, "has_auth": 0.3},
         "p": {"nonstandard_port": .4, "admin_context": .5, "verified_change": .45, "raw_ip_destination": .3},
         "fails": (3, 60), "cti_mal": .03, "cti_sus": .1, "cti_kev": .25, "sev": (1, 3)},
    ],
}
CLASS_PRIOR = {"true_positive": 0.32, "false_positive": 0.34, "benign_positive": 0.34}
BINARY = [f for f in FEATURES if f not in ("severity", "detector_confidence", "asset_criticality",
                                          "failed_logins_log", "cti_malicious_providers",
                                          "cti_suspicious_providers", "cti_max_confidence", "public_indicators")]


def _sample(rng: np.random.Generator, label: str, arch: dict) -> dict:
    f = {k: 0.0 for k in FEATURES}
    for k, p in arch["tel"].items():
        f[k] = float(rng.random() < p)
    if not any(f[k] for k in ("has_process", "has_network", "has_auth", "has_file")):
        f[next(iter(arch["tel"]))] = 1.0
    for k, p in arch["p"].items():
        f[k] = float(rng.random() < p)
    for k in BINARY:  # small background rate for everything else
        if k not in arch["p"] and k not in arch["tel"] and rng.random() < 0.015:
            f[k] = 1.0
    lo, hi = arch["sev"]
    f["severity"] = float(rng.integers(lo, hi + 1))
    conf_mean = {"true_positive": 0.72, "false_positive": 0.5, "benign_positive": 0.58}[label]
    f["detector_confidence"] = float(np.clip(rng.normal(conf_mean, 0.17), 0, 1)) if rng.random() > 0.2 else 0.5
    f["asset_criticality"] = float(rng.choice([0, 1, 2, 3], p=[0.2, 0.45, 0.25, 0.1]))
    if "fails" in arch and f.get("has_auth"):
        a, b = arch["fails"]
        f["failed_logins_log"] = round(math.log1p(int(rng.integers(a, b + 1))), 3)
    if rng.random() < arch.get("cti_mal", 0):
        f["cti_malicious_providers"] = float(rng.choice([1, 2, 3], p=[0.5, 0.35, 0.15]))
        lo_c, hi_c = arch.get("cti_mal_conf", (0.5, 1.0))
        f["cti_max_confidence"] = float(rng.uniform(lo_c, hi_c))
    if rng.random() < arch.get("cti_sus", 0):
        f["cti_suspicious_providers"] = float(rng.choice([1, 2], p=[0.7, 0.3]))
        f["cti_max_confidence"] = max(f["cti_max_confidence"], float(rng.uniform(0.2, 0.6)))
    f["cti_allowlisted"] = float(rng.random() < arch.get("cti_allow", 0.02))
    f["cti_kev"] = float(rng.random() < arch.get("cti_kev", 0.01))
    f["public_indicators"] = float(min(10, rng.poisson(1.6 if f["has_network"] else 0.6)
                                      + (f["cti_malicious_providers"] > 0)))
    return f


def generate(n: int = 12000, seed: int = 1337) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    labels = list(CLASS_PRIOR)
    rows = []
    for _ in range(n):
        label = str(rng.choice(labels, p=[CLASS_PRIOR[l] for l in labels]))
        archs = ARCHETYPES[label]
        arch = archs[int(rng.choice(len(archs), p=np.array([a["w"] for a in archs]) / sum(a["w"] for a in archs)))]
        f = _sample(rng, label, arch)
        # missing telemetry: the alert source did not forward a whole block
        for group, keys in GROUPS.items():
            flag = {"process": "has_process", "network": "has_network", "auth": "has_auth"}[group]
            if f[flag] and rng.random() < 0.06:
                f[flag] = 0.0
                for k in keys:
                    f[k] = 0.0
        # feature noise
        for k in BINARY:
            if rng.random() < 0.02:
                f[k] = 1.0 - f[k]
        true_label = label
        if rng.random() < 0.03:  # analyst label noise
            label = str(rng.choice([l for l in labels if l != label]))
        rows.append({**f, "label": label, "archetype": arch["name"], "generator_label": true_label})
    return pd.DataFrame(rows)
