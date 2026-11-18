---
id: PROC-087
title: "Mass account lock-out or deletion"
tactic: Impact
techniques: [T1531]
severity: high
tags: [account, availability]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-087 Mass account lock-out or deletion

## Detection signals
- Many accounts disabled or passwords changed in a short time
- Admin account used outside change windows

## Triage
- Identify the actor account
- Compare with change tickets

## Containment
- Disable the actor account and revoke sessions

## Eradication
- Restore affected accounts from backups or audit logs

## Recovery
- Protect privileged accounts with MFA and approvals

## Evidence to keep
- Directory audit logs

## Possible false positives
- Planned mass migrations
