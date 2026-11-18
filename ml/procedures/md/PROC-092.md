---
id: PROC-092
title: "IAM privilege escalation in the cloud"
tactic: Privilege Escalation
techniques: [T1098, T1078.004]
severity: high
tags: [gcp, iam, escalation]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-092 IAM privilege escalation in the cloud

## Detection signals
- setIamPolicy or role grants to a new principal
- Service account impersonation chains
- Owner or editor role added

## Triage
- Identify who changed the policy and when
- Compare with change tickets

## Containment
- Revert the binding, disable the principal

## Eradication
- Review all roles granted in the period

## Recovery
- Apply least privilege and alert on IAM changes

## Evidence to keep
- Admin activity audit logs

## Possible false positives
- Planned role changes
