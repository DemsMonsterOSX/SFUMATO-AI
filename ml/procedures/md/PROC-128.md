---
id: PROC-128
title: "Known-exploited CVE triage"
tactic: Vulnerability Management
techniques: []
severity: high
tags: [cve, kev, patching]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-128 Known-exploited CVE triage

## Detection signals
- A CVE appears in CISA KEV or has a high EPSS score and affects an inventoried product

## Triage
- Confirm the product and version are present and exposed
- Check for exploitation signs in the logs
- Prioritise internet-facing assets

## Containment
- Apply a workaround or virtual patch while waiting for the fix

## Eradication
- Patch within the KEV due date or the internal deadline

## Recovery
- Verify with a scan and update the inventory

## Evidence to keep
- Scan results, patch records

## Possible false positives
- Product present but feature disabled
