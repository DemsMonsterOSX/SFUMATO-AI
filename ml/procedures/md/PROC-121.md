---
id: PROC-121
title: "Handling false positives and benign positives"
tactic: Response
techniques: []
severity: low
tags: [triage, tuning]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-121 Handling false positives and benign positives

## Detection signals
- Activity matches a rule but is approved (change register, known software)

## Triage
- Check the change register and the approved software list
- Ask the owner if still unclear

## Containment
- No containment

## Eradication
- Document why it is benign

## Recovery
- Tune the detection or add an allow-list entry with an expiry date

## Evidence to keep
- Ticket or change reference

## Possible false positives
- Not applicable
