---
id: PROC-033
title: "Security event logs cleared"
tactic: Defense Evasion
techniques: [T1070.001]
severity: high
tags: [logs, evasion, windows]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-033 Security event logs cleared

## Detection signals
- Event 1102 or 104 (log cleared)
- Sudden gap in logs from a host
- wevtutil cl in command history

## Triage
- Identify who cleared the logs and when
- Recover logs from the SIEM or the forwarder
- Review activity just before the clearing

## Containment
- Isolate the host if the actor is unknown

## Eradication
- Restore logging settings and investigate the prior intrusion

## Recovery
- Forward logs off-host in real time

## Evidence to keep
- Forwarded copies of logs, event 1102, command history

## Possible false positives
- Planned log rotation during maintenance
