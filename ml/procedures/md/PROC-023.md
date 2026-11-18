---
id: PROC-023
title: "WMI event subscription persistence"
tactic: Persistence
techniques: [T1546.003]
severity: high
tags: [wmi, persistence]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-023 WMI event subscription persistence

## Detection signals
- New permanent event consumer using CommandLine or ActiveScript
- Filter triggered at startup or logon

## Triage
- List filters, consumers and bindings
- Hash the referenced payloads

## Containment
- Isolate the host if payloads are unknown

## Eradication
- Remove the three objects and the payload

## Recovery
- Add detections for new WMI subscriptions

## Evidence to keep
- WMI repository dump, Sysmon 19-21

## Possible false positives
- Management software that registers WMI events
