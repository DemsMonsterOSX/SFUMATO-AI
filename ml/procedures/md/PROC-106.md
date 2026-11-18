---
id: PROC-106
title: "LOIC HTTP flood (family DDoS attacks-LOIC-HTTP)"
tactic: Impact
techniques: [T1498.001, T1499.002]
severity: high
tags: [dataset, ddos, http]
dataset_families: [DDoS attacks-LOIC-HTTP]
status: draft-generated-not-validated
---

# PROC-106 LOIC HTTP flood (family DDoS attacks-LOIC-HTTP)

## Detection signals
- Large volumes of repetitive HTTP requests from many hosts
- Identical request signatures

## Triage
- Identify the shared signature and the distributed sources
- Experiment note: unseen recall 0.002, essentially invisible to a model that never saw it: add this family to training or use rate-based rules

## Containment
- Rate-limit, signature-based WAF rule, upstream scrubbing

## Eradication
- Keep controls until the flood ends

## Recovery
- Review capacity planning

## Evidence to keep
- Flow and web logs

## Possible false positives
- Popular events driving real traffic
