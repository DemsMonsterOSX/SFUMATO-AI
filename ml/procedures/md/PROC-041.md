---
id: PROC-041
title: "Password spraying"
tactic: Credential Access
techniques: [T1110.003]
severity: high
tags: [spraying, authentication, cloud]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-041 Password spraying

## Detection signals
- One or two attempts per account across many accounts
- A common weak password tried widely
- Failures spread over hours to avoid lockout

## Triage
- Aggregate failures by source and by password hint where available
- List accounts with a success after the failures

## Containment
- Block the source ranges
- Reset passwords of accounts that succeeded
- Enforce MFA on exposed endpoints

## Eradication
- Ban common passwords and enable smart lockout

## Recovery
- Monitor for retries from new sources

## Evidence to keep
- Identity provider sign-in logs aggregated by source

## Possible false positives
- Shared office NAT creating many failures from one IP
