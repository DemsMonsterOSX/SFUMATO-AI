---
id: PROC-108
title: "HOIC flood (family DDOS attack-HOIC)"
tactic: Impact
techniques: [T1498.001, T1499.002]
severity: high
tags: [dataset, ddos, http]
dataset_families: [DDOS attack-HOIC]
status: draft-generated-not-validated
---

# PROC-108 HOIC flood (family DDOS attack-HOIC)

## Detection signals
- High-rate HTTP floods with randomised headers and booster scripts
- Many short flows with two forward packets

## Triage
- Cluster requests by header patterns
- Experiment note: unseen recall 0.985, close to other floods the model knows

## Containment
- Rate-limit, challenge, scrub upstream

## Eradication
- Keep controls during the attack

## Recovery
- Return to normal

## Evidence to keep
- Flow and web logs

## Possible false positives
- Legitimate bursts
