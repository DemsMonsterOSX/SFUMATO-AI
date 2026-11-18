---
id: PROC-012
title: "Unix shell abuse and reverse shell"
tactic: Execution
techniques: [T1059.004]
severity: high
tags: [linux, shell, reverse-shell]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-012 Unix shell abuse and reverse shell

## Detection signals
- bash -i redirects to /dev/tcp, nc -e, python -c socket one-liners
- Web or database service spawns a shell
- Outbound connection from a server to an unusual port

## Triage
- Identify the parent service and the vulnerable component
- Check running processes and listening sockets
- Review shell history and recent file changes

## Containment
- Block the destination IP
- Isolate or snapshot the instance
- Rotate credentials present on the host

## Eradication
- Patch the entry point, remove backdoors and unknown cron jobs or keys

## Recovery
- Rebuild from a trusted image, restore data from a clean backup

## Evidence to keep
- auditd or EDR logs, process and network snapshot, disk snapshot

## Possible false positives
- Administrators using nc for diagnostics (rare, verify with the user)
