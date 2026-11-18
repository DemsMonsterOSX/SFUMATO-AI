---
id: PROC-046
title: "MFA fatigue (push bombing)"
tactic: Credential Access
techniques: [T1621]
severity: high
tags: [mfa, identity, push]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-046 MFA fatigue (push bombing)

## Detection signals
- Many MFA prompts the user did not start
- Approval at night after dozens of denials
- Login from an unfamiliar IP right after the approval

## Triage
- Contact the user and ask if they approved
- Review sign-in details and the session

## Containment
- Revoke sessions and force a password reset
- Re-register MFA methods

## Eradication
- Switch to number matching or phishing-resistant MFA

## Recovery
- Educate users to deny unexpected prompts and report them

## Evidence to keep
- MFA logs, sign-in logs

## Possible false positives
- User with a faulty authenticator
