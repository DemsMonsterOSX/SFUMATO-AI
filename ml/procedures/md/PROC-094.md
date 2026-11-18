---
id: PROC-094
title: "Exfiltration to an attacker-controlled cloud account"
tactic: Exfiltration
techniques: [T1537]
severity: high
tags: [cloud, transfer, snapshot]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-094 Exfiltration to an attacker-controlled cloud account

## Detection signals
- Snapshots or images shared with an external project
- Bucket copy jobs to an unknown destination

## Triage
- Identify the destination project and the principal
- List what was shared

## Containment
- Remove the sharing and revoke the principal

## Eradication
- Rotate secrets in the exposed assets

## Recovery
- Use organisation policy to restrict sharing

## Evidence to keep
- Audit logs

## Possible false positives
- Approved cross-project data sharing
