---
id: PROC-133
title: "Known benign software flagged as suspicious"
tactic: Response
techniques: []
severity: low
tags: [software, benign, sfumato]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-133 Known benign software flagged as suspicious

## Detection signals
- Rule matches a signed, approved application

## Triage
- Verify publisher, hash and the approved software list
- Check behaviour is within the expected profile

## Containment
- No containment

## Eradication
- Not applicable

## Recovery
- Add a scoped exclusion if the behaviour is expected

## Evidence to keep
- Software list entry, signature check

## Possible false positives
- Not applicable
