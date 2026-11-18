---
id: PROC-104
title: "Slowloris attack (family DoS attacks-Slowloris)"
tactic: Impact
techniques: [T1499.002]
severity: high
tags: [dataset, dos, slow]
dataset_families: [DoS attacks-Slowloris]
status: draft-generated-not-validated
---

# PROC-104 Slowloris attack (family DoS attacks-Slowloris)

## Detection signals
- Many half-open HTTP requests sending headers very slowly
- Connection table full, normal clients refused

## Triage
- Check connection durations and incomplete requests
- Experiment note: unseen recall 0.66; also the only family the KMeans anomaly detector partly flagged (0.23)

## Containment
- Enforce request-header timeouts, limit connections per IP, place a reverse proxy in front

## Eradication
- Use event-driven servers or a CDN

## Recovery
- Return to normal limits

## Evidence to keep
- Connection tables, server logs

## Possible false positives
- Clients on very slow mobile links
