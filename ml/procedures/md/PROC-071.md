---
id: PROC-071
title: "Exfiltration to a cloud storage service"
tactic: Exfiltration
techniques: [T1567.002]
severity: high
tags: [cloud, exfiltration, saas]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-071 Exfiltration to a cloud storage service

## Detection signals
- Uploads to personal cloud storage or file-sharing sites
- rclone or similar tools executed

## Triage
- Identify the user, the volume and the files
- Check the data classification

## Containment
- Block the service for the host, disable sharing links

## Eradication
- Remove the tool and review access of the user

## Recovery
- Apply data-loss-prevention policy

## Evidence to keep
- Proxy and CASB logs

## Possible false positives
- Approved corporate cloud storage accounts
