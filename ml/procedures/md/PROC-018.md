---
id: PROC-018
title: "Malicious Office macro"
tactic: Execution
techniques: [T1204.002, T1059.005]
severity: high
tags: [office, macro, phishing]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-018 Malicious Office macro

## Detection signals
- Word or Excel spawns cmd, PowerShell or wscript
- Document asks the user to enable content
- Macro with auto-open handlers and obfuscated strings

## Triage
- Extract the macro with oledump or similar in a sandbox
- List URLs and dropped files
- Check which users received or opened the file

## Containment
- Block macros from the Internet by policy
- Isolate hosts where the macro ran

## Eradication
- Remove dropped payloads and persistence

## Recovery
- Restore hosts, enforce Protected View and macro blocking

## Evidence to keep
- Document copy, sandbox report, process tree

## Possible false positives
- Finance templates that use signed internal macros
