---
id: PROC-065
title: "Proxying and tunnelling through a compromised host"
tactic: Command and Control
techniques: [T1090, T1572]
severity: medium
tags: [proxy, pivot, tunnel]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-065 Proxying and tunnelling through a compromised host

## Detection signals
- A server forwarding traffic between external IPs and internal hosts
- SSH or SOCKS tunnels from a workstation

## Triage
- Identify the listening ports and process
- Trace the connection endpoints

## Containment
- Kill the tunnel and isolate the host

## Eradication
- Remove the tool, close the entry vector

## Recovery
- Monitor for new listeners on workstations

## Evidence to keep
- Socket listings, flow logs

## Possible false positives
- Developers using SSH tunnels with approval
