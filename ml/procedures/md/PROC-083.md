---
id: PROC-083
title: "Volumetric network denial of service"
tactic: Impact
techniques: [T1498.001]
severity: high
tags: [ddos, flood, network]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-083 Volumetric network denial of service

## Detection signals
- Sudden traffic spike from many sources
- UDP or SYN floods saturating a link
- Packet rate far above baseline

## Triage
- Identify protocol, ports, sources and the target
- Confirm it is not a legitimate surge

## Containment
- Engage the upstream provider or a DDoS protection service
- Apply rate limits and ACLs, scrub traffic

## Eradication
- Keep rules until the attack ends

## Recovery
- Scale services back and review capacity

## Evidence to keep
- Flow data, packet captures, provider reports

## Possible false positives
- Marketing campaigns, product launches
