---
id: PROC-088
title: "Reflection and amplification attack"
tactic: Impact
techniques: [T1498.002]
severity: high
tags: [ddos, amplification, udp]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-088 Reflection and amplification attack

## Detection signals
- Very large UDP responses from DNS, NTP or memcached servers aimed at one target
- Source ports 53, 123 or 11211

## Triage
- Identify the reflector protocol and the victim
- Check that your own services are not used as reflectors

## Containment
- Filter the source ports at the edge, engage the upstream provider

## Eradication
- Close open resolvers and restrict UDP services

## Recovery
- Remove filters after the attack ends

## Evidence to keep
- Flow data, packet captures

## Possible false positives
- Large legitimate DNS answers (DNSSEC)
