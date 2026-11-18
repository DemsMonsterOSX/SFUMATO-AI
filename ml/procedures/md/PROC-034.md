---
id: PROC-034
title: "Security tool disabled or tampered with"
tactic: Defense Evasion
techniques: [T1562.001]
severity: high
tags: [edr, antivirus, tamper]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-034 Security tool disabled or tampered with

## Detection signals
- Defender or EDR service stopped, exclusions added, tamper protection off
- Agent stops reporting

## Triage
- Find the account and process that changed the settings
- Check for malware executed during the gap

## Containment
- Isolate the host
- Re-enable protection from the management console

## Eradication
- Remove exclusions and the tool used to disable protection

## Recovery
- Enable tamper protection and alert on policy changes

## Evidence to keep
- Agent logs, registry changes, management console audit

## Possible false positives
- IT adding temporary exclusions for a deployment
