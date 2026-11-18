---
id: PROC-109
title: "Botnet activity (family Bot, Zeus and Ares style)"
tactic: Command and Control
techniques: [T1071.001, T1105]
severity: high
tags: [dataset, botnet, c2]
dataset_families: [Bot]
status: draft-generated-not-validated
---

# PROC-109 Botnet activity (family Bot, Zeus and Ares style)

## Detection signals
- Periodic small HTTP calls to a C2, screenshots or file uploads
- Commands polled at intervals

## Triage
- Find the beacon interval, the destination and the process
- Experiment note: unseen recall 0.000, a model that never saw bots misses them completely; seen recall is 0.999

## Containment
- Block the C2, isolate the host

## Eradication
- Remove the bot and persistence, reset credentials

## Recovery
- Hunt for the same destination everywhere

## Evidence to keep
- Proxy logs, memory dump

## Possible false positives
- Telemetry agents with regular calls
