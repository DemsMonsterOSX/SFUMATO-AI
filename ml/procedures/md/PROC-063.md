---
id: PROC-063
title: "Ingress tool transfer"
tactic: Command and Control
techniques: [T1105]
severity: medium
tags: [download, tools, staging]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-063 Ingress tool transfer

## Detection signals
- Download of an executable by curl, wget, certutil or PowerShell
- Executable fetched from a paste site or file host

## Triage
- Hash the file and look it up
- Identify the initiating process

## Containment
- Block the source, isolate if the file is malicious

## Eradication
- Remove the file and any persistence

## Recovery
- Restrict outbound downloads of executables

## Evidence to keep
- Proxy logs, file hash

## Possible false positives
- Administrators downloading approved tools
