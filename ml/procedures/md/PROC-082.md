---
id: PROC-082
title: "Inhibit system recovery"
tactic: Impact
techniques: [T1490]
severity: high
tags: [backup, recovery, windows]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-082 Inhibit system recovery

## Detection signals
- bcdedit recovery disabled, shadow copies removed
- Backup agent stopped or catalogue deleted

## Triage
- Identify the actor and any ransomware stage
- Verify offsite backups

## Containment
- Isolate the host and protect backups

## Eradication
- Restore recovery settings and remove the tool

## Recovery
- Immutable offsite backup copies

## Evidence to keep
- Command history, backup logs

## Possible false positives
- Planned backup maintenance
