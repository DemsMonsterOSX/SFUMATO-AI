---
id: PROC-120
title: "Generic alert triage"
tactic: Response
techniques: []
severity: medium
tags: [triage, process]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-120 Generic alert triage

## Detection signals
- Any new alert without a matching playbook

## Triage
- Confirm the alert is real: source, rule, asset and user
- Enrich indicators with CTI
- Decide among true positive, benign positive, false positive or insufficient evidence
- Record the decision and its evidence

## Containment
- Apply containment only when evidence supports it

## Eradication
- Follow the specific procedure once classified

## Recovery
- Close with notes for detection tuning

## Evidence to keep
- Alert record, enrichment results

## Possible false positives
- See the specific procedure
