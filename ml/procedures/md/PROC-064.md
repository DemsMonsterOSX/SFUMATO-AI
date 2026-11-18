---
id: PROC-064
title: "Unauthorised remote access software"
tactic: Command and Control
techniques: [T1219]
severity: medium
tags: [remote-access, rmm, anydesk]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-064 Unauthorised remote access software

## Detection signals
- AnyDesk, TeamViewer or other RMM installed without a ticket
- Silent installation by a script

## Triage
- Identify who installed it and why
- Check the connection history

## Containment
- Block the software, disconnect sessions

## Eradication
- Uninstall and rotate any credentials entered

## Recovery
- Allow only approved remote tools

## Evidence to keep
- Software inventory, connection logs

## Possible false positives
- Approved vendor support sessions
