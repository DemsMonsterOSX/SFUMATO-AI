---
id: PROC-060
title: "Beaconing to a command-and-control server over HTTP(S)"
tactic: Command and Control
techniques: [T1071.001]
severity: high
tags: [c2, beacon, http]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-060 Beaconing to a command-and-control server over HTTP(S)

## Detection signals
- Regular connections at fixed intervals with small payloads
- Rare user agent or a domain registered recently
- Traffic to a raw IP over HTTPS

## Triage
- Compute the interval and jitter from proxy logs
- Check the domain and IP in CTI
- Identify the process making the calls

## Containment
- Block the destination
- Isolate the host

## Eradication
- Remove the implant and persistence, reset credentials used on the host

## Recovery
- Hunt for the same destination across all hosts

## Evidence to keep
- Proxy and flow logs, memory dump of the process

## Possible false positives
- Software updaters and telemetry agents with regular calls
