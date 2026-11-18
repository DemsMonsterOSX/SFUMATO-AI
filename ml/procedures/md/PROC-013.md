---
id: PROC-013
title: "Malicious script run by a script host (VBS, JS, HTA)"
tactic: Execution
techniques: [T1059.005, T1059.007]
severity: medium
tags: [vbscript, javascript, wscript]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-013 Malicious script run by a script host (VBS, JS, HTA)

## Detection signals
- wscript or cscript running a file from Temp or Downloads
- mshta loading a remote HTA
- Heavily obfuscated string concatenation

## Triage
- Collect the script and detonate it in a sandbox
- Extract the network indicators
- Check how it arrived (mail, download)

## Containment
- Block extracted domains
- Isolate the host if it contacted the Internet

## Eradication
- Remove the script and persistence

## Recovery
- Disable the script host by policy for users who do not need it

## Evidence to keep
- Script file, process tree, proxy logs

## Possible false positives
- Legacy business scripts (document owner confirmation)
