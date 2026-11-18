---
id: PROC-010
title: "Suspicious PowerShell execution"
tactic: Execution
techniques: [T1059.001]
severity: high
tags: [powershell, windows, script]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-010 Suspicious PowerShell execution

## Detection signals
- Encoded command lines (-enc, -EncodedCommand), download cradles, AMSI bypass strings
- PowerShell started by Office, a browser or a service
- Script block logging shows obfuscation

## Triage
- Decode the command and extract URLs, IPs and file paths
- Check parent process, user and host role
- Compare with the change register and approved admin tooling

## Containment
- Isolate the host if the payload is unknown or downloads code
- Block the extracted domains and hashes

## Eradication
- Remove artefacts written by the script and any scheduled tasks or run keys
- Enable constrained language mode where possible

## Recovery
- Restore the host after verification, keep script block logging on

## Evidence to keep
- Script block log (event 4104), process tree, network connections

## Possible false positives
- Administrators running approved deployment scripts (check the change register)
