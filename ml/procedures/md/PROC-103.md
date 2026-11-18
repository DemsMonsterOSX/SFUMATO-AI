---
id: PROC-103
title: "Keep-alive HTTP DoS by GoldenEye (family DoS attacks-GoldenEye)"
tactic: Impact
techniques: [T1499.002]
severity: high
tags: [dataset, dos, keepalive]
dataset_families: [DoS attacks-GoldenEye]
status: draft-generated-not-validated
---

# PROC-103 Keep-alive HTTP DoS by GoldenEye (family DoS attacks-GoldenEye)

## Detection signals
- Many persistent connections with random headers and requests
- Worker pool exhausted

## Triage
- Count connections per client and request cadence
- Experiment note: unseen recall 0.39, partly detected

## Containment
- Limit connections per IP, lower keep-alive timeout, WAF rules

## Eradication
- Tune server concurrency

## Recovery
- Restore settings after the attack

## Evidence to keep
- Server status, access logs

## Possible false positives
- Proxies aggregating many users
