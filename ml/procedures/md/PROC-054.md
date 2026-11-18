---
id: PROC-054
title: "Lateral movement with SSH"
tactic: Lateral Movement
techniques: [T1021.004]
severity: medium
tags: [ssh, lateral, linux]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-054 Lateral movement with SSH

## Detection signals
- SSH from a server to many internal servers
- New authorized_keys entries
- Key reuse across hosts

## Triage
- Review the source and the key used
- Check authorized_keys changes

## Containment
- Remove unauthorised keys, isolate the source host

## Eradication
- Rotate keys and passwords, enforce per-host keys

## Recovery
- Restrict SSH to bastions and log all sessions

## Evidence to keep
- auth.log, authorized_keys history

## Possible false positives
- Configuration management tools
