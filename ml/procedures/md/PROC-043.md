---
id: PROC-043
title: "LSASS memory credential dumping"
tactic: Credential Access
techniques: [T1003.001]
severity: critical
tags: [lsass, mimikatz, windows]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-043 LSASS memory credential dumping

## Detection signals
- Process opening lsass.exe with read access
- comsvcs.dll MiniDump or procdump targeting lsass
- Mimikatz strings or driver loaded

## Triage
- Identify the process and user
- Assume all credentials on the host are exposed
- Look for lateral movement afterwards

## Containment
- Isolate the host
- Reset credentials of every account that logged on, including service accounts

## Eradication
- Remove the tool, enable credential protection (LSA protection, Credential Guard)

## Recovery
- Rebuild the host and verify domain integrity

## Evidence to keep
- Sysmon event 10, EDR alert, dump file if present

## Possible false positives
- Security or backup software that reads lsass
