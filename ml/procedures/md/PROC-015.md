---
id: PROC-015
title: "WMI used for execution or remote commands"
tactic: Execution
techniques: [T1047]
severity: high
tags: [wmi, windows, lateral]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-015 WMI used for execution or remote commands

## Detection signals
- WmiPrvSE spawning cmd or PowerShell
- wmic process call create against remote hosts
- New WMI event subscriptions

## Triage
- Identify the source host and account
- Enumerate WMI subscriptions on the target
- Check for credential theft on the source

## Containment
- Isolate the source host
- Disable the account used

## Eradication
- Remove malicious subscriptions and filters
- Restrict remote WMI by firewall

## Recovery
- Restore hosts and enable WMI activity logging

## Evidence to keep
- WMI-Activity logs, Sysmon events 19-21, network logs

## Possible false positives
- Inventory or management tools using WMI
