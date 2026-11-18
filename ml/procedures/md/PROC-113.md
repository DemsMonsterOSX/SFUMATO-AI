---
id: PROC-113
title: "Infiltration after a malicious file and internal scan (family Infilteration)"
tactic: Initial Access
techniques: [T1566.001, T1105, T1046]
severity: high
tags: [dataset, infiltration, scan]
dataset_families: [Infilteration]
status: draft-generated-not-validated
---

# PROC-113 Infiltration after a malicious file and internal scan (family Infilteration)

## Detection signals
- File obtained from a mail or cloud link, then an internal port scan from that host
- A workstation behaving as a pivot

## Triage
- Trace the scan back to the first compromised host
- Experiment note: the hardest family, unseen recall 0.006 and only 0.23 even when seen; treat it with behavioural hunting, not only a classifier

## Containment
- Isolate the pivot host, block the file

## Eradication
- Remove the payload and the access path, reset credentials

## Recovery
- Segment the network and hunt for similar scans

## Evidence to keep
- Flow logs, endpoint timeline

## Possible false positives
- Approved internal scanners
