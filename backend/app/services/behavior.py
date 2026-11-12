"""Deterministic behavioural and contextual analysis of an incident.

Produces evidence (EV-BEH-*, EV-CTX-*, EV-INT-*) and the behavioural feature flags consumed by ML.
Command lines are inspected as text only; nothing is ever executed.
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timezone

from app.agents import prompt_guard
from app.schemas.incident import IncidentIn
from app.services.evidence import EvidenceBook
from app.services.org_context import load_org_context

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"}
SCRIPT_HOSTS = {"powershell.exe": "T1059.001", "pwsh.exe": "T1059.001", "cmd.exe": "T1059.003",
                "wscript.exe": "T1059.005", "cscript.exe": "T1059.005"}
LOLBINS = {"mshta.exe": "T1218.005", "rundll32.exe": "T1218.011", "regsvr32.exe": "T1218.010",
           "certutil.exe": "T1105", "bitsadmin.exe": "T1105"}
STANDARD_PORTS = {20, 21, 22, 25, 53, 80, 88, 110, 123, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995,
                  1433, 3268, 3389, 5985, 5986, 8080, 8443}

PATTERNS: dict[str, tuple[list[str], str, float, str]] = {
    # key: (regexes, technique, weight, title)
    "download_cradle": ([r"downloadstring", r"downloadfile", r"invoke-webrequest", r"\biwr\b", r"net\.webclient",
                         r"start-bitstransfer", r"certutil(?:\.exe)?\s.*-urlcache", r"\bcurl(?:\.exe)?\s+http",
                         r"\bwget\s+http"], "T1105", 18, "Remote payload download from the command line"),
    "in_memory_exec": ([r"\biex\b", r"invoke-expression", r"\[scriptblock\]::create"], "T1059.001", 10,
                       "In-memory script execution"),
    "credential_access": ([r"mimikatz", r"sekurlsa", r"procdump.*lsass", r"comsvcs(?:\.dll)?.*minidump",
                           r"lsass\.dmp"], "T1003.001", 30, "Credential dumping indicators"),
    "defense_evasion": ([r"set-mppreference\s.*-disable", r"-w(?:indowstyle)?\s+hid", r"-exec(?:utionpolicy)?\s+bypass",
                         r"amsiutils", r"add-mppreference\s.*-exclusion"], "T1562.001", 10,
                        "Defence evasion switches or security tooling tampering"),
    "persistence": ([r"schtasks(?:\.exe)?\s.*/create", r"currentversion\\run", r"new-service\b", r"\bsc(?:\.exe)?\s+create"],
                    "T1053.005", 14, "Persistence mechanism created"),
    "lateral_movement": ([r"\bpsexec", r"wmic(?:\.exe)?\s.*?/node", r"invoke-command\s.*-computername", r"enter-pssession"],
                         "T1021.002", 14, "Remote execution on another host"),
    "ransomware": ([r"vssadmin(?:\.exe)?\s+delete\s+shadows", r"wbadmin\s+delete\s+catalog", r"bcdedit.*recoveryenabled\s+no"],
                   "T1486", 30, "Ransomware preparation commands"),
}
_COMPILED = {k: [re.compile(p, re.IGNORECASE) for p in v[0]] for k, v in PATTERNS.items()}
RE_ENC = re.compile(r"\s-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand|ec)\s+[A-Za-z0-9+/=<>A-Z_]{8,}",
                    re.IGNORECASE)
RE_TICKET = re.compile(r"^[A-Z]{2,6}-\d{4}-\d{2,6}$")


def _lower(v: str | None) -> str:
    return (v or "").strip().lower()


def _basename(v: str | None) -> str:
    return _lower(v).replace("/", "\\").rsplit("\\", 1)[-1]


def analyze(incident: IncidentIn, book: EvidenceBook, decoded_command: str | None) -> dict:
    org = load_org_context()
    f: dict[str, float] = {k: 0.0 for k in (
        "office_parent_shell", "encoded_command", "download_cradle", "lolbin", "credential_access",
        "defense_evasion", "persistence", "lateral_movement", "ransomware", "nonstandard_port", "raw_ip_destination",
        "large_upload", "failed_logins_log", "geo_anomaly", "success_after_failures", "off_hours", "verified_change",
        "unverified_change", "admin_context", "approved_software", "masquerading", "sanctioned_destination",
        "noisy_rule", "prompt_injection")}
    notes: list[str] = []

    proc = incident.process
    pname = _basename(proc.name if proc else None)
    parent = _basename(proc.parent if proc else None)
    cmd = proc.command_line if proc and proc.command_line else ""
    analysed_text = cmd + ("\n" + decoded_command if decoded_command else "")

    # --- Process behaviour -------------------------------------------------------------------------
    if proc:
        if parent in OFFICE and (pname in SCRIPT_HOSTS or pname in LOLBINS):
            f["office_parent_shell"] = 1
            book.add("behavior", polarity="malicious", kind="office_spawns_interpreter", weight=22,
                     title=f"{parent} spawned {pname}",
                     description="An Office application launched a script interpreter or system binary, a "
                                 "classic pattern of malicious documents (macro / exploit).",
                     source="Sfumato behavioural rules", mitre=["T1566.001", "T1204.002", SCRIPT_HOSTS.get(pname, LOLBINS.get(pname, "T1059.001"))],
                     data={"parent": parent, "process": pname})
        if RE_ENC.search(" " + cmd):
            f["encoded_command"] = 1
            book.add("behavior", polarity="suspicious", kind="encoded_command", weight=14,
                     title="Encoded PowerShell command",
                     description="The command line uses -EncodedCommand to hide its content."
                                 + (" The payload was decoded statically for inspection." if decoded_command else
                                    " The payload could not be decoded (redacted or invalid)."),
                     source="Sfumato behavioural rules", mitre=["T1027", "T1140"],
                     data={"decoded_preview": (decoded_command or "")[:400]})
        if pname in LOLBINS:
            f["lolbin"] = 1
            book.add("behavior", polarity="suspicious", kind="lolbin", weight=12,
                     title=f"System binary proxy execution via {pname}",
                     description=f"{pname} is frequently abused to proxy execution of malicious code.",
                     source="Sfumato behavioural rules", mitre=[LOLBINS[pname]])
        for key, (_, tech, weight, title) in PATTERNS.items():
            hit = next((rx for rx in _COMPILED[key] if rx.search(analysed_text)), None)
            if hit:
                f[key] = 1
                book.add("behavior", polarity="malicious" if weight >= 18 else "suspicious", kind=key, weight=weight,
                         title=title, description=f"Command line matches pattern `{hit.pattern}`.",
                         source="Sfumato behavioural rules", mitre=[tech],
                         data={"matched_in": "decoded payload" if decoded_command and hit.search(decoded_command) else "command line"})

        # Approved software / masquerading
        signer = _lower(proc.signer)
        for sw in org.get("approved_software", []):
            if pname == sw["name"].lower():
                if proc.signed is not False and signer and signer == sw["signer"].lower():
                    if sw.get("admin_only") and _lower(incident.user.username if incident.user else None) not in \
                            [u.lower() for u in org["admin_users"]]:
                        book.add("context", polarity="suspicious", kind="admin_tool_non_admin", weight=12,
                                 title=f"{sw['product']} used by a non-administrative account",
                                 description="The tool is approved for administrators only.",
                                 source="Sfumato Local Intelligence (software catalogue)")
                        break
                    f["approved_software"] = 1
                    book.add("context", polarity="benign", benign_class="misidentification", kind="approved_software",
                             weight=30, title=f"Approved, correctly signed software: {sw['product']}",
                             description=f"{pname} is in the organisation's software catalogue and the code-signing "
                                         f"publisher matches ({sw['signer']}).",
                             source="Sfumato Local Intelligence (software catalogue)", data=sw)
                elif signer and signer != sw["signer"].lower() or proc.signed is False:
                    f["masquerading"] = 1
                    book.add("behavior", polarity="malicious", kind="masquerading", weight=24,
                             title=f"{pname} has an unexpected signer",
                             description=f"Binary name matches approved software but the signer is "
                                         f"'{proc.signer or 'unsigned'}' instead of '{sw['signer']}'.",
                             source="Sfumato behavioural rules", mitre=["T1036.005"])
                break

    if incident.file and incident.file.name and not proc:
        fname = _basename(incident.file.name)
        for sw in org.get("approved_software", []):
            if fname == sw["name"].lower() and _lower(incident.file.signer) == sw["signer"].lower() \
                    and incident.file.signed is not False:
                f["approved_software"] = 1
                book.add("context", polarity="benign", benign_class="misidentification", kind="approved_software",
                         weight=30, title=f"Approved, correctly signed file: {sw['product']}",
                         description="The detected file is in the software catalogue with a matching signer.",
                         source="Sfumato Local Intelligence (software catalogue)", data=sw)

    # --- Network behaviour -------------------------------------------------------------------------
    net = incident.network
    if net:
        if net.destination_port and net.destination_port not in STANDARD_PORTS and (net.direction or "outbound") != "inbound":
            f["nonstandard_port"] = 1
            book.add("behavior", polarity="suspicious", kind="nonstandard_port", weight=8,
                     title=f"Outbound connection on non-standard port {net.destination_port}",
                     description="Command-and-control frameworks often use uncommon ports.",
                     source="Sfumato behavioural rules", mitre=["T1571"])
        if net.destination_ip and not net.destination_domain and not net.url and net.protocol and \
                net.protocol.upper() in ("HTTP", "HTTPS"):
            f["raw_ip_destination"] = 1
            book.add("behavior", polarity="suspicious", kind="raw_ip_web", weight=6,
                     title="Web traffic to a bare IP address",
                     description="HTTP(S) to an IP address without a hostname is unusual for legitimate software.",
                     source="Sfumato behavioural rules", mitre=["T1071.001"])
        if net.bytes_out and net.bytes_out > 50 * 1024 * 1024:
            f["large_upload"] = 1
            book.add("behavior", polarity="suspicious", kind="large_upload", weight=10,
                     title=f"Large outbound transfer ({net.bytes_out // (1024 * 1024)} MiB)",
                     description="Volume is consistent with possible data exfiltration.",
                     source="Sfumato behavioural rules", mitre=["T1041"])
        dom = _lower(net.destination_domain)
        if dom and any(dom == s or dom.endswith("." + s) for s in org.get("sanctioned_domains", [])):
            f["sanctioned_destination"] = 1
            book.add("context", polarity="benign", benign_class="misidentification", kind="sanctioned_destination",
                     weight=15, title=f"Destination {dom} is sanctioned by the organisation",
                     description="The domain belongs to the organisation's list of approved vendor services.",
                     source="Sfumato Local Intelligence (sanctioned destinations)")

    # --- Authentication behaviour ------------------------------------------------------------------
    auth = incident.authentication
    if auth:
        fails = auth.failed_attempts or 0
        f["failed_logins_log"] = round(math.log1p(fails), 3)
        if fails >= 10:
            book.add("behavior", polarity="malicious" if fails >= 30 else "suspicious", kind="brute_force",
                     weight=22 if fails >= 30 else 14, title=f"{fails} failed authentication attempts",
                     description="Repeated failures are consistent with password guessing or spraying.",
                     source="Sfumato behavioural rules", mitre=["T1110"])
            if _lower(auth.result) == "success":
                f["success_after_failures"] = 1
                book.add("behavior", polarity="malicious", kind="success_after_failures", weight=16,
                         title="Successful logon after repeated failures",
                         description="A successful authentication followed the failures: the account may be compromised.",
                         source="Sfumato behavioural rules", mitre=["T1078"])
        if auth.source_country and auth.usual_country and auth.source_country.upper() != auth.usual_country.upper():
            f["geo_anomaly"] = 1
            book.add("behavior", polarity="suspicious", kind="geo_anomaly", weight=10,
                     title=f"Logon from unusual country ({auth.source_country} instead of {auth.usual_country})",
                     description="Geographic anomaly relative to the user's usual location.",
                     source="Sfumato behavioural rules", mitre=["T1078"])
            if auth.mfa is False and _lower(auth.result) == "success":
                book.add("behavior", polarity="suspicious", kind="no_mfa", weight=6,
                         title="Successful logon without MFA from an unusual location",
                         description="No second factor was presented.", source="Sfumato behavioural rules")

    # --- Organisational context --------------------------------------------------------------------
    username = _lower(incident.user.username if incident.user else None)
    hostname = (incident.asset.hostname or "").upper() if incident.asset else ""
    md = incident.metadata
    ticket = (md.change_ticket or "").strip().upper()
    if ticket:
        rec = org["change_register"].get(ticket)
        verified = False
        if rec:
            host_ok = hostname in [h.upper() for h in rec.get("hosts", [])]
            user_ok = username in [u.lower() for u in rec.get("users", [])]
            in_window = True
            try:
                ws = datetime.fromisoformat(rec["window_start"].replace("Z", "+00:00"))
                we = datetime.fromisoformat(rec["window_end"].replace("Z", "+00:00"))
                in_window = ws <= incident.timestamp <= we
            except (KeyError, ValueError):
                pass
            verified = host_ok and user_ok and in_window
            if verified:
                f["verified_change"] = 1
                book.add("context", polarity="benign", benign_class="authorization", kind="verified_change", weight=40,
                         title=f"Activity covered by approved change {ticket}",
                         description=f"'{rec.get('title')}' — host, user and time window match the change register "
                                     f"(approved by {rec.get('approved_by', 'n/a')}).",
                         source="Sfumato Local Intelligence (change register)", data={"ticket": ticket, **rec})
            else:
                notes.append(f"Change {ticket} exists but does not match host/user/window")
        if not verified:
            f["unverified_change"] = 1
            book.add("context", polarity="suspicious", kind="unverified_change", weight=6,
                     title=f"Change ticket {ticket} could not be verified",
                     description="A change ticket was quoted in the alert but does not match the change register "
                                 "for this host, user and time. Self-declared justifications are not trusted.",
                     source="Sfumato Local Intelligence (change register)")
    elif md.maintenance_window:
        book.add("context", polarity="benign", benign_class="authorization", kind="maintenance_flag", weight=6,
                 title="Alert flagged as occurring during maintenance",
                 description="Self-declared by the alert source; weak evidence without a verified change.",
                 source="Alert metadata")

    if username and username in [u.lower() for u in org["admin_users"]] and \
            hostname in [h.upper() for h in org["admin_hosts"]]:
        f["admin_context"] = 1
        book.add("context", polarity="benign", benign_class="authorization", kind="admin_context", weight=18,
                 title=f"Administrative account {username} on management host {hostname}",
                 description="Both the account and the host are expected to run administrative tooling.",
                 source="Sfumato Local Intelligence (admin inventory)")

    rule = md.detection_rule or incident.alert.name
    noisy = org.get("noisy_detection_rules", {})
    if rule in noisy:
        f["noisy_rule"] = 1
        book.add("context", polarity="benign", benign_class="misidentification", kind="noisy_rule", weight=12,
                 title=f"Detection rule '{rule}' has a documented high false-positive rate",
                 description=str(noisy[rule]), source="Sfumato Local Intelligence (detection tuning log)")

    wh = org["working_hours_utc"]
    hour = incident.timestamp.astimezone(timezone.utc).hour
    if not (wh["start"] <= hour < wh["end"]):
        f["off_hours"] = 1
        book.add("context", polarity="suspicious", kind="off_hours", weight=4,
                 title=f"Activity outside working hours ({hour:02d}:00 UTC)",
                 description="Weak signal on its own.", source="Sfumato behavioural rules")

    # --- Integrity: prompt-injection attempts inside incident data ----------------------------------
    hits = prompt_guard.scan(incident.model_dump(mode="json"))
    if hits:
        f["prompt_injection"] = 1
        book.add("integrity", polarity="suspicious", kind="prompt_injection", weight=10,
                 title="Instruction-like content found in incident fields",
                 description="Some fields contain text that tries to instruct an AI system. It was neutralised and "
                             "treated strictly as data. Its presence is itself suspicious.",
                 source="Sfumato prompt guard", data={"locations": hits[:5]})

    telemetry = {
        "process": incident.process is not None,
        "network": incident.network is not None,
        "authentication": incident.authentication is not None,
        "file": incident.file is not None,
        "user": incident.user is not None,
        "asset": incident.asset is not None,
    }
    if not any(telemetry[k] for k in ("process", "network", "authentication", "file")):
        book.add("integrity", polarity="neutral", kind="limited_telemetry", weight=0,
                 title="Limited telemetry",
                 description="The alert carries no process, network, authentication or file details; behavioural "
                             "analysis could not be performed.", source="Sfumato behavioural rules")
    return {"features": f, "telemetry": telemetry, "notes": notes,
            "analysed_command": bool(cmd), "decoded_command": decoded_command}
