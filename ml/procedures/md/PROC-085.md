---
id: PROC-085
title: "Resource hijacking (crypto-mining)"
tactic: Impact
techniques: [T1496]
severity: medium
tags: [cryptomining, cloud, cpu]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-085 Resource hijacking (crypto-mining)

## Detection signals
- Sustained 100% CPU or GPU usage
- Connections to mining pools or stratum ports
- Unknown processes with random names

## Triage
- Identify the process and the entry point
- Check cloud billing for spikes

## Containment
- Kill the process, block pool domains, isolate or stop the instance

## Eradication
- Remove the miner and persistence, close the entry vector

## Recovery
- Rotate keys and enable budget alerts

## Evidence to keep
- Process list, flow logs, billing data

## Possible false positives
- Legitimate compute-heavy jobs
