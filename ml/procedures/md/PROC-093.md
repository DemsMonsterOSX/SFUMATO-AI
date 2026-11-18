---
id: PROC-093
title: "Unauthorised compute instance creation"
tactic: Impact
techniques: [T1578, T1496]
severity: high
tags: [gcp, compute, mining]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-093 Unauthorised compute instance creation

## Detection signals
- Instances in unusual regions or with large machine types
- Creation by an unfamiliar principal

## Triage
- Identify the creator and the instance purpose
- Check network traffic and billing

## Containment
- Stop the instances and snapshot disks for analysis

## Eradication
- Delete the resources, revoke the principal's access

## Recovery
- Restrict allowed regions and machine types by policy

## Evidence to keep
- Audit logs, billing report, instance metadata

## Possible false positives
- Approved experiments by the team
