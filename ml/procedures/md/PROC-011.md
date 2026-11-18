---
id: PROC-011
title: "Windows command shell abuse"
tactic: Execution
techniques: [T1059.003]
severity: medium
tags: [cmd, windows, living-off-the-land]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-011 Windows command shell abuse

## Detection signals
- cmd.exe spawned by a document or script host
- Chained commands: whoami, net user, ipconfig in a short window
- Use of certutil, bitsadmin or curl to fetch files

## Triage
- Review the full command line and parent process
- Determine if it is a manual admin session
- Look for follow-up activity on the same host

## Containment
- Isolate the host if reconnaissance is followed by lateral movement

## Eradication
- Remove downloaded tools and reset exposed credentials

## Recovery
- Return the host after a clean scan

## Evidence to keep
- Process creation logs (4688 or Sysmon 1), command lines, network logs

## Possible false positives
- Help-desk troubleshooting scripts
