---
id: PROC-050
title: "Internal network scanning"
tactic: Discovery
techniques: [T1046, T1018]
severity: medium
tags: [scan, nmap, discovery]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-050 Internal network scanning

## Detection signals
- One host contacting many ports or many hosts
- SYN scans with few completed connections
- Sequential connections to 445, 3389 and 22

## Triage
- Identify the scanning host and its user
- Compare with approved vulnerability scanners
- Check what the host did before the scan

## Containment
- Isolate the host if unapproved
- Block the scanner at internal firewalls

## Eradication
- Remove the tool and look for the initial compromise

## Recovery
- Segment networks to limit scan reach

## Evidence to keep
- Flow logs, firewall logs

## Possible false positives
- Approved vulnerability and asset-discovery scanners
