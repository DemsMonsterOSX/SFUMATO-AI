---
id: PROC-100
title: "FTP brute force (CIC-IDS2018 family FTP-BruteForce)"
tactic: Credential Access
techniques: [T1110.001]
severity: medium
tags: [dataset, ftp, bruteforce]
dataset_families: [FTP-BruteForce]
status: draft-generated-not-validated
---

# PROC-100 FTP brute force (CIC-IDS2018 family FTP-BruteForce)

## Detection signals
- Many short flows to port 21 from one source
- Repeated failed FTP logins (530 responses)

## Triage
- Count attempts per source and check for a success
- Experiment note: a model that never saw this family still detected it (recall 1.00), the pattern resembles other brute force

## Containment
- Block the source, disable FTP or require SFTP with keys

## Eradication
- Reset any account that succeeded

## Recovery
- Retire plain FTP

## Evidence to keep
- FTP server logs, flow records on port 21

## Possible false positives
- Backup jobs with stale credentials
