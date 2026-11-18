---
id: PROC-032
title: "Process injection"
tactic: Defense Evasion
techniques: [T1055]
severity: high
tags: [injection, memory, evasion]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-032 Process injection

## Detection signals
- Remote thread created in a trusted process
- Unsigned memory regions with execute rights
- Browser or system process making unusual network connections

## Triage
- Dump the suspicious process memory
- Identify the injecting process
- Check network destinations of the host process

## Containment
- Isolate the host and kill the injected process

## Eradication
- Remove the injector and persistence, reset credentials in memory

## Recovery
- Rebuild the host if the injector is unknown

## Evidence to keep
- Memory dump, EDR alert, network logs

## Possible false positives
- Security tools and accessibility software that hook processes
