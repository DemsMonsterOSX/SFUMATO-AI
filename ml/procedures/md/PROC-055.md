---
id: PROC-055
title: "Pass-the-hash or stolen ticket use"
tactic: Lateral Movement
techniques: [T1550.002]
severity: high
tags: [ntlm, kerberos, lateral]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-055 Pass-the-hash or stolen ticket use

## Detection signals
- NTLM logons with no matching interactive logon
- Ticket use from a host that never requested it
- Admin logons from unusual hosts

## Triage
- Identify the account and the origin host
- Look for credential theft on the origin

## Containment
- Isolate the origin, reset the account and the krbtgt twice if golden ticket is suspected

## Eradication
- Remove tools, enforce NTLM restrictions

## Recovery
- Tier administrative accounts

## Evidence to keep
- Domain controller and host logon events

## Possible false positives
- Legacy applications using NTLM
