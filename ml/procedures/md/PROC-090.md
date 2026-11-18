---
id: PROC-090
title: "Leaked service account key"
tactic: Credential Access
techniques: [T1552.001, T1078.004]
severity: critical
tags: [gcp, service-account, key]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-090 Leaked service account key

## Detection signals
- Key found in a repository or paste site
- API calls from an IP outside the usual ranges
- Unexpected resource creation

## Triage
- Identify the key and the roles of the service account
- Review audit logs for its usage
- Check for new keys, roles and resources

## Containment
- Disable and delete the key
- Revoke recent tokens, restrict the account with conditions

## Eradication
- Remove resources created by the actor, review IAM bindings

## Recovery
- Use workload identity instead of long-lived keys, enable secret scanning

## Evidence to keep
- Cloud audit logs, repository history

## Possible false positives
- Automation running from an approved CI runner
