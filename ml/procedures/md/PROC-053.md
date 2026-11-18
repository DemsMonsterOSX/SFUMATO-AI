---
id: PROC-053
title: "Lateral movement through SMB and admin shares"
tactic: Lateral Movement
techniques: [T1021.002, T1570]
severity: high
tags: [smb, lateral, psexec]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-053 Lateral movement through SMB and admin shares

## Detection signals
- Writes to ADMIN$ or C$ from non-admin hosts
- Executable copied then a service or task created remotely

## Triage
- Find the source and the account
- List files copied
- Check for follow-on execution

## Containment
- Isolate the source host and disable the account

## Eradication
- Remove copied tools and services, reset credentials

## Recovery
- Block SMB between workstations, use LAPS for local admins

## Evidence to keep
- Events 5140 and 5145, network flows

## Possible false positives
- Software deployment systems
