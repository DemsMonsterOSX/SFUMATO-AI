---
id: PROC-051
title: "Account and group discovery"
tactic: Discovery
techniques: [T1087, T1069]
severity: low
tags: [discovery, active-directory]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-051 Account and group discovery

## Detection signals
- net user /domain, net group, dsquery, AD enumeration tools (BloodHound-style LDAP bursts)

## Triage
- Identify the source account and host
- Check whether the account normally does this

## Containment
- Monitor closely, isolate if combined with other suspicious steps

## Eradication
- Remove tools found on the host

## Recovery
- Tune detections for large LDAP queries

## Evidence to keep
- Directory query logs, process creation logs

## Possible false positives
- Administrators and inventory tools
