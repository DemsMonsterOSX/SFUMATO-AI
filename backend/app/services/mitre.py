"""Curated subset of MITRE ATT&CK Enterprise techniques used by the behavioural rules.

IDs and names follow ATT&CK Enterprise (https://attack.mitre.org). The AI agent may only cite
techniques present in this table, which prevents invented technique IDs from reaching the report.
"""
from __future__ import annotations

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "Execution"},
    "T1059.005": {"name": "Command and Scripting Interpreter: Visual Basic", "tactic": "Execution"},
    "T1204.002": {"name": "User Execution: Malicious File", "tactic": "Execution"},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
    "T1218.005": {"name": "System Binary Proxy Execution: Mshta", "tactic": "Defense Evasion"},
    "T1218.010": {"name": "System Binary Proxy Execution: Regsvr32", "tactic": "Defense Evasion"},
    "T1218.011": {"name": "System Binary Proxy Execution: Rundll32", "tactic": "Defense Evasion"},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion"},
    "T1036.005": {"name": "Masquerading: Match Legitimate Name or Location", "tactic": "Defense Evasion"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    "T1219": {"name": "Remote Access Software", "tactic": "Command and Control"},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1569.002": {"name": "System Services: Service Execution", "tactic": "Execution"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution"},
    "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task", "tactic": "Execution, Persistence"},
    "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  "tactic": "Persistence"},
    "T1560.001": {"name": "Archive Collected Data: Archive via Utility", "tactic": "Collection"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
}


def describe(tid: str) -> dict[str, str]:
    t = TECHNIQUES.get(tid)
    if not t:
        return {"id": tid, "name": "Unknown technique", "tactic": "", "url": ""}
    return {"id": tid, **t, "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}


def is_known(tid: str) -> bool:
    return tid in TECHNIQUES
