---
id: PROC-123
title: "Evidence collection and chain of custody"
tactic: Response
techniques: []
severity: medium
tags: [forensics, evidence]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-123 Evidence collection and chain of custody

## Detection signals
- A confirmed or likely incident that may need legal follow-up

## Triage
- Record who collected what, when and how
- Hash every artefact
- Collect volatile data first (memory, connections, processes)

## Containment
- Isolate rather than power off when memory matters

## Eradication
- Keep originals untouched, work on copies

## Recovery
- Store evidence read-only with access logging

## Evidence to keep
- Hash list, acquisition notes

## Possible false positives
- Not applicable
