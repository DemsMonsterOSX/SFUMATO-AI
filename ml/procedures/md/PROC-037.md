---
id: PROC-037
title: "Masquerading as a legitimate process or file"
tactic: Defense Evasion
techniques: [T1036]
severity: medium
tags: [masquerading, naming]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-037 Masquerading as a legitimate process or file

## Detection signals
- System binary name in a wrong path
- Misspelt service name (svch0st.exe)
- Valid name but unsigned

## Triage
- Compare path, signature and hash with the genuine file
- Check the network activity of the process

## Containment
- Isolate if confirmed

## Eradication
- Delete the fake binary and its persistence

## Recovery
- Alert on system binary names outside system paths

## Evidence to keep
- File hash, signature check, process list

## Possible false positives
- Portable copies of tools by administrators
