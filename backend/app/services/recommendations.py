"""Context-aware response recommendations.

DISPLAY ONLY. Nothing in this module (or anywhere in Sfumato) executes remediation: no blocking,
no isolation, no account changes, no firewall changes. Every recommendation carries
`automated: False` and `display_only: True`, and tests assert it.
"""
from __future__ import annotations

from app.schemas.evidence import Evidence


PROCESS_KINDS = ("office_spawns_interpreter", "encoded_command", "lolbin", "download_cradle", "in_memory_exec",
                 "credential_access", "defense_evasion", "persistence", "lateral_movement", "ransomware", "masquerading")


def _ids(evidence: list[Evidence], *kinds: str, category: str | None = None, polarity: tuple = ()) -> list[str]:
    return [e.id for e in evidence
            if (not kinds or e.kind in kinds) and (category is None or e.category == category)
            and (not polarity or e.polarity in polarity)]


def recommend(verdict: dict, evidence: list[Evidence], incident: dict, indicators: list[dict]) -> list[dict]:
    v = verdict["verdict"]
    crit = (incident.get("asset") or {}).get("criticality") or "medium"
    host = (incident.get("asset") or {}).get("hostname") or "the affected endpoint"
    user = (incident.get("user") or {}).get("username") or "the user"
    recs: list[dict] = []

    def add(action, priority, explanation, evidence_ids, impact, risk, category):
        recs.append({"id": f"REC-{len(recs) + 1:02d}", "action": action, "priority": priority,
                     "explanation": explanation, "evidence_ids": evidence_ids, "operational_impact": impact,
                     "risk": risk, "category": category, "display_only": True, "automated": False})

    hostile = v in ("TRUE_POSITIVE", "INCONCLUSIVE")
    proc_ev = _ids(evidence, *PROCESS_KINDS, polarity=("malicious", "suspicious"))
    cti_mal = _ids(evidence, "cti_malicious", "cti_suspicious")
    net_ev = _ids(evidence, "nonstandard_port", "raw_ip_web", "large_upload")
    auth_ev = _ids(evidence, "brute_force", "success_after_failures", "geo_anomaly", "no_mfa")

    if v == "TRUE_POSITIVE" or v == "INCONCLUSIVE":
        add("Escalate to a SOC analyst", "P1" if v == "TRUE_POSITIVE" else "P2",
            "Automated triage " + ("confirmed malicious activity." if v == "TRUE_POSITIVE" else
                                   "could not reach a reliable verdict; a human decision is required."),
            verdict.get("factors", {}).get("behavior", {}).get("evidence_ids", [])[:5] + cti_mal[:3],
            "Analyst time", "Low", "escalation")
    if hostile and proc_ev:
        add(f"Investigate the affected endpoint ({host})", "P1" if v == "TRUE_POSITIVE" else "P2",
            "Collect volatile data, running processes and persistence locations before anything changes.",
            proc_ev, "None (read-only forensic collection)", "Low", "investigation")
        add("Review process execution history", "P2",
            "Rebuild the full parent/child chain and review the (decoded) command lines around the alert time.",
            proc_ev, "None", "Low", "investigation")
    if cti_mal:
        add("Validate malicious indicators before blocking", "P1" if v == "TRUE_POSITIVE" else "P2",
            "Confirm each flagged indicator with a second source and check for shared hosting/CDN usage before "
            "any block is considered by an authorised operator.",
            cti_mal, "Blocking shared infrastructure can disrupt legitimate services",
            "Medium — false blocks are possible on shared IPs/domains", "containment-preparation")
    if hostile and net_ev:
        add("Investigate suspicious outbound traffic", "P2",
            "Review proxy/firewall/DNS logs for the same destinations and similar beacons from other hosts.",
            net_ev + cti_mal, "None", "Low", "investigation")
    if hostile and auth_ev:
        add(f"Review user authentication activity for {user}", "P1" if v == "TRUE_POSITIVE" else "P2",
            "Check sign-in logs, MFA prompts, source IPs and active sessions for this account.",
            auth_ev, "None", "Low", "identity")
        if _ids(evidence, "success_after_failures") and v == "TRUE_POSITIVE":
            add("Consider credential reset and session revocation (analyst decision)", "P1",
                "A successful logon after many failures suggests the password may be compromised.",
                _ids(evidence, "success_after_failures", "brute_force"),
                "User must re-authenticate; possible short interruption", "Low", "identity")
    if _ids(evidence, "lateral_movement", "credential_access"):
        if hostile:
            add("Investigate potential lateral movement", "P1",
                "Look for the same account or tooling on other hosts (remote service creation, SMB/WMI/WinRM).",
                _ids(evidence, "lateral_movement", "credential_access"), "None", "Low", "investigation")
    if v == "TRUE_POSITIVE" and proc_ev and (crit in ("high", "critical") or _ids(
            evidence, "credential_access", "ransomware", "office_spawns_interpreter")):
        add(f"Consider endpoint isolation of {host} (analyst decision)", "P1",
            "Isolation limits spread while the investigation continues. Sfumato never isolates automatically.",
            proc_ev + cti_mal, "The user loses network access; business processes on the host stop",
            "High if the host is business-critical — requires owner approval", "containment-preparation")
    if _ids(evidence, "known_exploited_vulnerability"):
        add("Verify patch status for the referenced CVE(s)", "P1",
            "The CVE is listed in CISA KEV (known to be exploited in the wild).",
            _ids(evidence, "known_exploited_vulnerability"), "Possible maintenance window", "Low", "vulnerability")
    if _ids(evidence, "prompt_injection"):
        add("Review the integrity of the alert source", "P2",
            "Incident fields contained instruction-like text aimed at AI systems; an attacker may be trying to "
            "influence automated triage.", _ids(evidence, "prompt_injection"), "None", "Low", "integrity")
    if v == "FALSE_POSITIVE":
        rule = (incident.get("metadata") or {}).get("detection_rule") or (incident.get("alert") or {}).get("name")
        add(f"Tune the detection rule '{rule}'", "P3",
            "The detection misidentified approved or sanctioned activity; add a precise, reviewed exclusion.",
            _ids(evidence, polarity=("benign",)), "Fewer false alerts", "Low if the exclusion is narrow", "tuning")
    if v == "LEGITIMATE_ACTIVITY":
        add("Document the authorised activity and close the alert", "P4",
            "Link the alert to the change record / admin context for audit purposes.",
            _ids(evidence, polarity=("benign",)), "None", "Low", "documentation")
    public = [i["value"] for i in indicators if i["shareable"]][:5]
    add("Search for related incidents", "P3" if v in ("FALSE_POSITIVE", "LEGITIMATE_ACTIVITY") else "P2",
        "Search the incident history and SIEM for the same indicators, host and user"
        + (f" ({', '.join(public)})." if public else "."),
        cti_mal or proc_ev, "None", "Low", "hunting")
    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    recs.sort(key=lambda r: order[r["priority"]])
    for n, r in enumerate(recs, 1):
        r["id"] = f"REC-{n:02d}"
    return recs
