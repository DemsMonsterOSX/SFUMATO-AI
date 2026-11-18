---
id: PROC-021
title: "New local or domain account created by an attacker"
tactic: Persistence
techniques: [T1136, T1098]
severity: high
tags: [account, persistence, privilege]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-021 New local or domain account created by an attacker

## Detection signals
- Account creation outside the provisioning process
- User added to administrators or domain admins
- Password or key changes on a privileged account

## Triage
- Identify who created the account and from which host
- Check what the account accessed
- Compare with HR or ticket records

## Containment
- Disable the account and revoke its sessions
- Isolate the originating host

## Eradication
- Remove the account and unauthorised group memberships, rotate related secrets

## Recovery
- Audit privileged groups and enable alerts on membership changes

## Evidence to keep
- Events 4720, 4728, 4732, 4738, directory audit logs

## Possible false positives
- Joiner process outside business hours
