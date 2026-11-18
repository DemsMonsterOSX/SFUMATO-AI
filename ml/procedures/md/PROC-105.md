---
id: PROC-105
title: "Slow HTTP body or read attack (family DoS attacks-SlowHTTPTest)"
tactic: Impact
techniques: [T1499.002]
severity: high
tags: [dataset, dos, slow-post]
dataset_families: [DoS attacks-SlowHTTPTest]
status: draft-generated-not-validated
---

# PROC-105 Slow HTTP body or read attack (family DoS attacks-SlowHTTPTest)

## Detection signals
- POST bodies sent byte by byte, or responses read very slowly
- Thread exhaustion

## Triage
- Inspect slow transfers and their sources
- Experiment note: unseen recall 1.00

## Containment
- Set minimum data rates and body timeouts, limit connections

## Eradication
- Harden the web server configuration

## Recovery
- Restore capacity

## Evidence to keep
- Access logs with timings

## Possible false positives
- Users uploading files over poor links
