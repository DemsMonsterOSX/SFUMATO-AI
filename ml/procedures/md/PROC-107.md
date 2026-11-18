---
id: PROC-107
title: "LOIC UDP flood (family DDOS attack-LOIC-UDP)"
tactic: Impact
techniques: [T1498.001]
severity: high
tags: [dataset, ddos, udp]
dataset_families: [DDOS attack-LOIC-UDP]
status: draft-generated-not-validated
---

# PROC-107 LOIC UDP flood (family DDOS attack-LOIC-UDP)

## Detection signals
- UDP packets with fixed small payload at very high rate
- Extremely long flows with very many forward packets

## Triage
- Measure packet rates per source and port
- Experiment note: the KMeans anomaly detector flagged it (recall 1.00) because its behaviour is extreme, but only 537 test flows

## Containment
- Filter UDP at the edge, engage the upstream provider

## Eradication
- Close unused UDP services

## Recovery
- Restore normal filtering

## Evidence to keep
- Flow data, packet captures

## Possible false positives
- Game or streaming traffic
