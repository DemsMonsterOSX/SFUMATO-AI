---
id: PROC-081
title: "Destructive data wiping"
tactic: Impact
techniques: [T1485, T1561]
severity: critical
tags: [wiper, destruction]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-081 Destructive data wiping

## Detection signals
- Raw disk writes by an unknown process
- Mass deletion and overwritten boot records

## Triage
- Stop spread by isolating segments
- Identify the initial access and the scope

## Containment
- Isolate networks, power down unaffected critical systems if needed

## Eradication
- Remove the wiper and the access path

## Recovery
- Rebuild from backups and verify integrity

## Evidence to keep
- Samples, logs from unaffected hosts, backup status

## Possible false positives
- Secure-erase of decommissioned drives
