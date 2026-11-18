---
id: PROC-045
title: "Credentials stored in files or password stores"
tactic: Credential Access
techniques: [T1552.001, T1555]
severity: medium
tags: [credentials, secrets, files]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-045 Credentials stored in files or password stores

## Detection signals
- Access to browser credential databases or keychains by a non-browser process
- Secrets found in repositories or shares

## Triage
- Identify the process reading the stores
- Search shares and repositories for exposed secrets

## Containment
- Revoke and rotate the exposed secrets

## Eradication
- Remove the secrets from files and adopt a secret manager

## Recovery
- Enable secret scanning in CI

## Evidence to keep
- File access logs, repository scan results

## Possible false positives
- Backup software reading profile folders
