---
id: PROC-042
title: "Credential stuffing"
tactic: Credential Access
techniques: [T1110.004]
severity: high
tags: [stuffing, authentication, leak]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-042 Credential stuffing

## Detection signals
- Login attempts with valid-format credentials from a breach list
- High success rate on rarely used accounts
- Automation fingerprints (headless browser)

## Triage
- Compare accounts with known breach exposure
- Check successful logins for abnormal activity

## Containment
- Rate-limit and add bot protection
- Force password reset for affected accounts

## Eradication
- Enable MFA and breached-password checks

## Recovery
- Notify affected users

## Evidence to keep
- Web and authentication logs, device fingerprints

## Possible false positives
- Password-manager autofill from corporate users
