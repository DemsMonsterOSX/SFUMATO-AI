---
id: PROC-031
title: "UAC bypass or token manipulation"
tactic: Privilege Escalation
techniques: [T1548.002, T1134]
severity: medium
tags: [uac, token, windows]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-031 UAC bypass or token manipulation

## Detection signals
- Auto-elevating binary launched with an unusual child
- Process running with a token from another user

## Triage
- Review the parent chain and the registry keys touched
- Check which admin actions followed

## Containment
- Isolate the host if admin actions were malicious

## Eradication
- Remove the registry changes and payloads, remove local admin rights where unneeded

## Recovery
- Enforce least privilege and UAC at the highest level

## Evidence to keep
- Sysmon process and registry events

## Possible false positives
- Legacy software that auto-elevates
