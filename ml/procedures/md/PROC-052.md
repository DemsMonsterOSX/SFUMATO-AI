---
id: PROC-052
title: "Lateral movement over RDP"
tactic: Lateral Movement
techniques: [T1021.001]
severity: high
tags: [rdp, lateral, windows]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-052 Lateral movement over RDP

## Detection signals
- RDP from a workstation to another workstation
- Logon type 10 from unusual sources
- Chain of RDP hops

## Triage
- Map the hop chain
- Validate with the owners of the accounts
- Check tools copied to the targets

## Containment
- Disable the account, block RDP between workstations

## Eradication
- Remove tools, reset credentials along the chain

## Recovery
- Restrict RDP to jump hosts with MFA

## Evidence to keep
- Events 4624 (type 10), 1149, firewall logs

## Possible false positives
- IT support sessions
