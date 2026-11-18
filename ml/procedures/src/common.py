"""Shared helper to declare one response procedure compactly.

Every procedure follows the NIST SP 800-61 lifecycle (detect/triage, contain, eradicate, recover) plus evidence and false
positives. ATT&CK ids come from the public MITRE ATT&CK knowledge base. Content is GENERATED DRAFT material written by an AI
assistant for a course project: it is NOT validated by a security professional and must be reviewed before operational use.
"""
PROCEDURES: list[dict] = []


def P(pid, title, tactic, techniques, severity, tags, signals, triage, contain, eradicate, recover, evidence, fp, families=()):
    PROCEDURES.append({
        "id": pid, "title": title, "tactic": tactic, "techniques": list(techniques), "severity": severity, "tags": list(tags),
        "signals": signals, "triage": triage, "contain": contain, "eradicate": eradicate, "recover": recover,
        "evidence": evidence, "false_positives": fp, "dataset_families": list(families),
        "status": "draft-generated-not-validated",
    })
