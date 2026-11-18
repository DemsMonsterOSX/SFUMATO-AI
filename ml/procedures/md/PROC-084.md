---
id: PROC-084
title: "Application-layer (HTTP) denial of service"
tactic: Impact
techniques: [T1499.002]
severity: high
tags: [dos, http, layer7]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-084 Application-layer (HTTP) denial of service

## Detection signals
- Many requests to costly endpoints from few clients
- High request rate with the same headers
- Connections held open for a long time

## Triage
- Identify request patterns and sources
- Check server resource usage

## Containment
- Enable rate limiting and WAF rules, add connection timeouts
- Block abusive sources

## Eradication
- Tune server limits and caching

## Recovery
- Return to normal limits gradually

## Evidence to keep
- Web logs, WAF logs, resource graphs

## Possible false positives
- Crawlers and flash crowds
