---
id: PROC-057
title: "Cloud service and resource discovery"
tactic: Discovery
techniques: [T1526]
severity: medium
tags: [cloud, discovery, gcp]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-057 Cloud service and resource discovery

## Detection signals
- Burst of list and describe API calls by an unusual principal
- Calls from a new IP or user agent

## Triage
- Identify the principal and the credential type
- Review the calls that followed

## Containment
- Disable the key or session, add conditions to the role

## Eradication
- Rotate the credential and review IAM bindings

## Recovery
- Enable audit logs for data access

## Evidence to keep
- Cloud audit logs

## Possible false positives
- Inventory scripts and cost-management tools
