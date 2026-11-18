---
id: PROC-131
title: "Suspicious authentication sequence"
tactic: Credential Access
techniques: [T1078]
severity: medium
tags: [authentication, sfumato]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-131 Suspicious authentication sequence

## Detection signals
- Failures followed by a success, odd hours, new device

## Triage
- Compare with the user's baseline
- Contact the user
- Review actions after the success

## Containment
- Reset credentials and revoke sessions if not confirmed

## Eradication
- Remove artefacts created in the session

## Recovery
- Add conditional access

## Evidence to keep
- Sign-in logs

## Possible false positives
- Travel, new laptop
