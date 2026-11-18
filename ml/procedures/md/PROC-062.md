---
id: PROC-062
title: "Domain generation algorithm (DGA) activity"
tactic: Command and Control
techniques: [T1568.002]
severity: high
tags: [dga, dns, botnet]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-062 Domain generation algorithm (DGA) activity

## Detection signals
- Many NXDOMAIN answers for random-looking domains
- A host cycling through new domains

## Triage
- List domains and cluster by pattern
- Find the process generating the lookups

## Containment
- Block the pattern at DNS, isolate the host

## Eradication
- Remove the malware, reset credentials

## Recovery
- Add the pattern to DNS monitoring

## Evidence to keep
- DNS logs

## Possible false positives
- Misconfigured software probing random names
