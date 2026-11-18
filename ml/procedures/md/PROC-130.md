---
id: PROC-130
title: "Known malicious domain contacted"
tactic: Command and Control
techniques: [T1071.001]
severity: high
tags: [ioc, domain, cti, sfumato]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-130 Known malicious domain contacted

## Detection signals
- DNS or proxy logs show a domain classified malicious by CTI

## Triage
- Check data origin and freshness of the CTI hit
- Identify the process and user behind the request
- Look for other contacts with the domain

## Containment
- Block the domain, isolate the host if a process beyond the browser is involved

## Eradication
- Remove malware found on the host

## Recovery
- Monitor for related domains

## Evidence to keep
- DNS logs, CTI response with its origin

## Possible false positives
- Stale indicators, shared hosting
