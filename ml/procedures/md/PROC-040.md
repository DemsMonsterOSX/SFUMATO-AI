---
id: PROC-040
title: "Password guessing against a single account"
tactic: Credential Access
techniques: [T1110.001]
severity: medium
tags: [bruteforce, authentication]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-040 Password guessing against a single account

## Detection signals
- Many failed logins on one account from one or few IPs
- Lockout events

## Triage
- Identify source IPs and whether any login succeeded
- Check the account's privileges

## Containment
- Block or rate-limit the source
- Reset the password if a success was observed

## Eradication
- Enforce strong passwords and MFA

## Recovery
- Review lockout thresholds

## Evidence to keep
- Authentication logs (4625 and 4624), source IP data

## Possible false positives
- User who forgot a password or a service with stale credentials
