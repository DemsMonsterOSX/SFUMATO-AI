---
id: PROC-004
title: "Use of valid accounts from unusual locations"
tactic: Initial Access
techniques: [T1078]
severity: high
tags: [identity, account, login]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-004 Use of valid accounts from unusual locations

## Detection signals
- Impossible travel between two sign-ins
- Sign-in from a new country, ASN or anonymising service
- Successful login after many failures

## Triage
- Contact the user through a separate channel
- Compare device, user agent and IP with the user's history
- List actions taken in the session (mail rules, downloads, role changes)

## Containment
- Revoke tokens and sessions, force password reset
- Require MFA re-registration
- Temporarily disable the account if misuse is confirmed

## Eradication
- Remove malicious mailbox rules, OAuth apps and API keys created by the actor

## Recovery
- Re-enable the account with a conditional-access policy for the risky location

## Evidence to keep
- Identity provider logs, session list, audit log of the account

## Possible false positives
- Travelling users, VPN or corporate proxy egress points, mobile carrier IP changes
