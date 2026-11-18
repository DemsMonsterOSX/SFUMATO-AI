---
id: PROC-102
title: "HTTP flood by the Hulk tool (family DoS attacks-Hulk)"
tactic: Impact
techniques: [T1499.002]
severity: high
tags: [dataset, dos, http]
dataset_families: [DoS attacks-Hulk]
status: draft-generated-not-validated
---

# PROC-102 HTTP flood by the Hulk tool (family DoS attacks-Hulk)

## Detection signals
- Many unique URLs requested to defeat caching
- Random user agents and referrers from few sources

## Triage
- Compare request diversity with normal traffic
- Experiment note: unseen recall 0.92, a model trained on other floods generalises well

## Containment
- Rate-limit, WAF challenge, block sources

## Eradication
- Keep rules during the attack and tune caching

## Recovery
- Scale back after the attack ends

## Evidence to keep
- Web server and WAF logs

## Possible false positives
- Flash crowd
