---
id: PROC-101
title: "SSH brute force (family SSH-Bruteforce)"
tactic: Credential Access
techniques: [T1110.001]
severity: medium
tags: [dataset, ssh, bruteforce]
dataset_families: [SSH-Bruteforce]
status: draft-generated-not-validated
---

# PROC-101 SSH brute force (family SSH-Bruteforce)

## Detection signals
- Many connections to port 22 from one source with few bytes
- auth.log full of Failed password

## Triage
- List sources and usernames tried, check for Accepted entries
- Experiment note: unseen by the model, recall only 0.06 (seen: 1.00): do not rely on a model that has not been trained on this family

## Containment
- Block the source, enable fail2ban or rate limits, allow SSH only from a bastion

## Eradication
- Disable password authentication, rotate exposed keys

## Recovery
- Monitor for retries from new IPs

## Evidence to keep
- auth.log, flow records on port 22

## Possible false positives
- Automation with a wrong key
