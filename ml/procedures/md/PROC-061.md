---
id: PROC-061
title: "DNS tunnelling or DNS-based C2"
tactic: Command and Control
techniques: [T1071.004, T1572]
severity: high
tags: [dns, tunnel, c2]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-061 DNS tunnelling or DNS-based C2

## Detection signals
- Very long or high-entropy subdomains
- Large volume of TXT or NULL queries to one domain
- A single host generating most queries to a rare domain

## Triage
- Collect queries to the domain and measure volume
- Identify the host and process

## Containment
- Sinkhole or block the domain, isolate the host

## Eradication
- Remove the tunnelling tool

## Recovery
- Force DNS through monitored resolvers

## Evidence to keep
- DNS logs, resolver statistics

## Possible false positives
- Anti-virus or CDN services that use long DNS names
