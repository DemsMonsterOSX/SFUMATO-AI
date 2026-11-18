---
id: PROC-110
title: "Web login brute force (family Brute Force -Web)"
tactic: Credential Access
techniques: [T1110, T1190]
severity: medium
tags: [dataset, web, bruteforce]
dataset_families: [Brute Force -Web]
status: draft-generated-not-validated
---

# PROC-110 Web login brute force (family Brute Force -Web)

## Detection signals
- Many POSTs to a login form with changing passwords
- Same session repeatedly failing

## Triage
- Count attempts per account and source
- Experiment note: very rare family (185 test flows), supervised recall 0.22 in the multiclass test

## Containment
- Rate-limit, add CAPTCHA or lockout, block sources

## Eradication
- Enforce MFA and strong passwords

## Recovery
- Monitor the login endpoint

## Evidence to keep
- Web logs

## Possible false positives
- Users mistyping passwords
