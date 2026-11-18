---
id: PROC-017
title: "Execution through a Windows service"
tactic: Execution
techniques: [T1569.002, T1543.003]
severity: high
tags: [service, windows, psexec]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-017 Execution through a Windows service

## Detection signals
- Service installed with a random name or a binary in ADMIN$
- PsExec-like service created remotely
- Service running from a temp directory

## Triage
- Identify the creating host and account (event 7045)
- Collect the service binary
- Check for lateral movement from the same account

## Containment
- Stop and disable the service
- Isolate hosts involved

## Eradication
- Remove the service and binary, reset the abused credentials

## Recovery
- Rebuild hosts if kernel-level tools were present

## Evidence to keep
- Event 7045, registry service key, binary copy

## Possible false positives
- Remote administration by IT using approved tools
