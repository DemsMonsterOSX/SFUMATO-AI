---
id: PROC-002
title: "Phishing e-mail with a malicious link"
tactic: Initial Access
techniques: [T1566.002]
severity: high
tags: [email, phishing, credentials]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-002 Phishing e-mail with a malicious link

## Detection signals
- Link to a recently registered or look-alike domain
- Login page that mimics the corporate portal
- Several users click the same URL in a short window

## Triage
- Extract the URL chain (shorteners, redirects) without visiting it from a corporate host
- Check proxy logs for every host that requested the domain
- Determine whether credentials were submitted (POST requests, sign-in anomalies)

## Containment
- Block the domain and URL at the proxy and DNS
- Force sign-out and password reset for users who submitted credentials
- Revoke active sessions and MFA registrations created recently

## Eradication
- Review mailbox rules and OAuth grants added after the click
- Hunt for logins from the phishing infrastructure

## Recovery
- Re-enable accounts after a reset and MFA re-enrolment
- Report the domain to the registrar and hosting provider

## Evidence to keep
- URL, redirect chain, proxy and DNS logs, identity provider sign-in logs

## Possible false positives
- Internal awareness exercises that use look-alike domains
