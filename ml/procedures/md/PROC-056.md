---
id: PROC-056
title: "WinRM or PowerShell remoting abuse"
tactic: Lateral Movement
techniques: [T1021.006]
severity: medium
tags: [winrm, remoting, lateral]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-056 WinRM or PowerShell remoting abuse

## Detection signals
- Remote PowerShell sessions from non-admin hosts
- wsmprovhost spawning shells

## Triage
- Identify the source and the commands executed
- Confirm with the owner

## Containment
- Disable the account, restrict WinRM by firewall

## Eradication
- Remove artefacts and reset credentials

## Recovery
- Limit remoting to admin hosts and log transcripts

## Evidence to keep
- WinRM operational log, script block logs

## Possible false positives
- Automation and management tooling
