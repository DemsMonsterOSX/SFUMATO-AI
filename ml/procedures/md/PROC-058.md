---
id: PROC-058
title: "Theft of SSH private keys"
tactic: Credential Access
techniques: [T1552.004]
severity: high
tags: [ssh, keys, linux]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-058 Theft of SSH private keys

## Detection signals
- Read access to ~/.ssh by an unusual process
- Key used from a new host or IP
- Keys without passphrases found in backups

## Triage
- Identify which keys were exposed and where they are authorised
- Review recent logins with these keys

## Containment
- Remove the public keys from authorized_keys everywhere

## Eradication
- Issue new keys with passphrases or certificates

## Recovery
- Use short-lived SSH certificates and a bastion

## Evidence to keep
- auth.log, file access audit

## Possible false positives
- Backup tools reading home directories
