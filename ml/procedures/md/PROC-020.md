---
id: PROC-020
title: "Registry run key persistence"
tactic: Persistence
techniques: [T1547.001]
severity: medium
tags: [registry, windows, autorun]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-020 Registry run key persistence

## Detection signals
- New value in Run or RunOnce pointing to AppData or Temp
- Value name mimicking a legitimate product

## Triage
- Hash the target file and check the signature
- Find the process that wrote the key

## Containment
- Isolate the host if malicious

## Eradication
- Delete the value and the payload

## Recovery
- Monitor the key on all hosts

## Evidence to keep
- Registry export, Sysmon event 13, file hash

## Possible false positives
- Installers adding startup entries
