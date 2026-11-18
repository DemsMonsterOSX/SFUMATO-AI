---
id: PROC-086
title: "Website defacement"
tactic: Impact
techniques: [T1491]
severity: medium
tags: [web, defacement, integrity]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-086 Website defacement

## Detection signals
- Home page content replaced
- Unexpected file changes in the web root

## Triage
- Find the file changes and the access vector
- Check for web shells and credential theft

## Containment
- Take the site offline or serve a clean copy

## Eradication
- Restore from known-good code and patch the vulnerability

## Recovery
- Monitor integrity and credentials of the CMS

## Evidence to keep
- Web logs, file timeline, CMS audit log

## Possible false positives
- Authorised content changes
