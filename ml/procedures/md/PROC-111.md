---
id: PROC-111
title: "Cross-site scripting attempt (family Brute Force -XSS)"
tactic: Initial Access
techniques: [T1190]
severity: medium
tags: [dataset, web, xss]
dataset_families: [Brute Force -XSS]
status: draft-generated-not-validated
---

# PROC-111 Cross-site scripting attempt (family Brute Force -XSS)

## Detection signals
- Script tags and event handlers in parameters
- Reflected payloads in responses

## Triage
- Check input handling and output encoding of the targeted endpoints
- Experiment note: rare family (74 test flows), multiclass recall 0.46

## Containment
- WAF rule for the pattern, patch the page

## Eradication
- Encode output and add a content security policy

## Recovery
- Re-test the endpoint

## Evidence to keep
- Web logs, request bodies

## Possible false positives
- Rich-text editors posting HTML
