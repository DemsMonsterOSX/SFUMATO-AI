---
id: PROC-070
title: "Large data transfer to an external destination"
tactic: Exfiltration
techniques: [T1041, T1048]
severity: high
tags: [exfiltration, data, egress]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-070 Large data transfer to an external destination

## Detection signals
- Outbound volume far above the host's baseline
- Transfers at night to a rare destination
- Compressed archives created just before the transfer

## Triage
- Quantify bytes and destinations
- Identify the data involved and its classification
- Check who owns the account

## Containment
- Block the destination, isolate the host or account

## Eradication
- Remove staging files and the tool that sent them

## Recovery
- Notify the data owner and legal if personal data is involved

## Evidence to keep
- Flow logs, proxy logs, file listings of the staging folder

## Possible false positives
- Scheduled backups to an approved cloud destination
