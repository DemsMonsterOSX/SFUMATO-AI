---
id: PROC-035
title: "Obfuscated or packed payload"
tactic: Defense Evasion
techniques: [T1027, T1140]
severity: medium
tags: [obfuscation, packer, malware]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-035 Obfuscated or packed payload

## Detection signals
- High-entropy files, Base64 blobs decoded at runtime
- Packers or custom crypters flagged by YARA

## Triage
- Unpack in a sandbox and extract configuration and C2
- Hash all layers

## Containment
- Block extracted indicators

## Eradication
- Remove the payload and persistence

## Recovery
- Share indicators with threat-intel partners

## Evidence to keep
- Sample, sandbox report, YARA matches

## Possible false positives
- Commercial software protected by packers
