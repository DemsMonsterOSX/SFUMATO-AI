---
id: PROC-022
title: "Web shell on a server"
tactic: Persistence
techniques: [T1505.003]
severity: critical
tags: [web, web-shell, server]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-022 Web shell on a server

## Detection signals
- Recently modified script in the web root
- Requests to an unusual file with a POST body and short responses
- Web server process spawning system commands

## Triage
- Find the file and its creation time
- Correlate with the initial exploitation
- Review all requests to that file

## Containment
- Take a snapshot, then isolate the server
- Block the actor IPs

## Eradication
- Remove the shell, patch the vulnerability, rebuild if root access was possible

## Recovery
- Redeploy from clean code with file-integrity monitoring

## Evidence to keep
- Copy of the shell, web logs, file timeline

## Possible false positives
- Legitimate admin consoles uploaded by developers
