---
id: PROC-066
title: "Command and control through a legitimate web service"
tactic: Command and Control
techniques: [T1102]
severity: medium
tags: [c2, saas, cloud]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-066 Command and control through a legitimate web service

## Detection signals
- Regular small calls to a code-sharing, paste or chat API from a server
- API tokens embedded in malware

## Triage
- Identify the account or channel used and the calling process
- Preserve content with a legal request if needed

## Containment
- Block the specific account path where possible, isolate the host

## Eradication
- Remove the implant

## Recovery
- Report the abuse to the service provider

## Evidence to keep
- Proxy logs, memory dump

## Possible false positives
- Developers using the same service
