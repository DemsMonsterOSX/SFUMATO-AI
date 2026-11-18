---
id: PROC-044
title: "Kerberoasting"
tactic: Credential Access
techniques: [T1558.003]
severity: high
tags: [kerberos, active-directory]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-044 Kerberoasting

## Detection signals
- Burst of service ticket requests (event 4769) with RC4 encryption
- One account requesting tickets for many SPNs

## Triage
- Identify the requesting account and host
- List the service accounts targeted and their password age

## Containment
- Disable or reset the requester if compromised
- Rotate passwords of targeted service accounts

## Eradication
- Use long random passwords or managed service accounts and AES

## Recovery
- Monitor 4769 patterns

## Evidence to keep
- Domain controller logs

## Possible false positives
- Inventory tools requesting many tickets
