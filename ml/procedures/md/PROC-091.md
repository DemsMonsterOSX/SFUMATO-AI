---
id: PROC-091
title: "Publicly exposed cloud storage bucket"
tactic: Collection
techniques: [T1530]
severity: high
tags: [gcp, bucket, exposure]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-091 Publicly exposed cloud storage bucket

## Detection signals
- allUsers or allAuthenticatedUsers on a bucket or object
- Data access from unknown IPs

## Triage
- List the exposed objects and their sensitivity
- Check access logs for downloads

## Containment
- Remove public access and enable public access prevention

## Eradication
- Rotate any secrets stored in the bucket

## Recovery
- Notify the data owner and legal if personal data was exposed

## Evidence to keep
- Bucket IAM policy, data access logs

## Possible false positives
- Intentionally public website assets
