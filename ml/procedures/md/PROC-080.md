---
id: PROC-080
title: "Ransomware encryption in progress"
tactic: Impact
techniques: [T1486, T1490]
severity: critical
tags: [ransomware, encryption, backup]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-080 Ransomware encryption in progress

## Detection signals
- Mass file renames with a new extension
- Ransom notes dropped in many folders
- Shadow copies deleted (vssadmin delete shadows)

## Triage
- Identify patient zero and the extent
- Verify backups are intact and offline
- Do not pay or contact the actor without legal and management

## Containment
- Disconnect infected hosts from the network immediately
- Disable accounts used and block C2
- Protect backups from the network

## Eradication
- Remove the malware and the actor's access, patch the entry vector

## Recovery
- Restore from clean backups after validation, rebuild domain controllers if needed

## Evidence to keep
- Ransom note, encrypted file samples, process and network timeline

## Possible false positives
- Legitimate bulk encryption by backup or archiving tools
