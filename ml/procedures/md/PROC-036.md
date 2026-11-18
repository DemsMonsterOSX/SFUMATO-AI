---
id: PROC-036
title: "Living-off-the-land binary abuse (LOLBins)"
tactic: Defense Evasion
techniques: [T1218]
severity: medium
tags: [lolbin, windows, proxy-execution]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-036 Living-off-the-land binary abuse (LOLBins)

## Detection signals
- rundll32, regsvr32, mshta or msiexec loading remote content
- certutil used to download or decode files

## Triage
- Review command line arguments and the parent process
- Resolve any URLs contacted

## Containment
- Block destinations
- Isolate the host if a payload ran

## Eradication
- Remove staged files and persistence

## Recovery
- Apply attack-surface-reduction rules for these binaries

## Evidence to keep
- Process creation logs, proxy logs

## Possible false positives
- Installers calling msiexec or regsvr32 normally
