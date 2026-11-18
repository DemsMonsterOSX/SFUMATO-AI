---
id: PROC-030
title: "Local privilege escalation by exploitation"
tactic: Privilege Escalation
techniques: [T1068]
severity: high
tags: [privilege, exploit, cve]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-030 Local privilege escalation by exploitation

## Detection signals
- Low-privilege process suddenly running as SYSTEM or root
- Crash or kernel error followed by elevated activity
- Public exploit for a CVE on the host's OS version

## Triage
- Identify the process chain and user
- Check OS patch level against known exploited CVEs
- Look for new admin accounts or tools

## Containment
- Isolate the host
- Disable the user account

## Eradication
- Patch the vulnerability, remove tools, rebuild if kernel compromise is suspected

## Recovery
- Redeploy from a hardened image

## Evidence to keep
- EDR timeline, patch inventory, memory image if available

## Possible false positives
- Installers that elevate through approved mechanisms
