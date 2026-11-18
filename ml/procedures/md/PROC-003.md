---
id: PROC-003
title: "Exploitation of an internet-facing web application"
tactic: Initial Access
techniques: [T1190]
severity: critical
tags: [web, vulnerability, cve]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-003 Exploitation of an internet-facing web application

## Detection signals
- Unexpected requests to admin or script endpoints, long query strings, encoded payloads
- Web server spawns shell processes
- Known-exploited CVE affecting the product (see CISA KEV)

## Triage
- Identify product, version and whether the CVE applies
- Search web logs for the exploit pattern over the last 30 days
- Check for new files in web directories and outbound connections from the server

## Containment
- Restrict access with a WAF rule or by IP while patching
- Isolate the server if code execution is confirmed
- Rotate secrets stored on the host

## Eradication
- Apply the vendor patch or workaround and rebuild from a trusted image if compromised
- Remove web shells and unauthorised accounts

## Recovery
- Return to service behind monitoring with the patch verified by a scan
- Add a detection for the exploit pattern

## Evidence to keep
- Web and WAF logs, file listing with timestamps, memory and disk image if compromised

## Possible false positives
- Vulnerability scanners run by the security team
