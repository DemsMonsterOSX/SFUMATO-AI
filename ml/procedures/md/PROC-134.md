---
id: PROC-134
title: "Threat hunting after new indicators"
tactic: Response
techniques: []
severity: medium
tags: [hunting, ioc]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-134 Threat hunting after new indicators

## Detection signals
- New indicators from CTI or from an incident

## Triage
- Search DNS, proxy, EDR and authentication data for the indicators over the past 90 days
- Pivot on infrastructure (IP, ASN, certificates)
- Record hits and negative results

## Containment
- Contain hosts with confirmed hits

## Eradication
- Follow the specific procedure

## Recovery
- Create detections from the findings

## Evidence to keep
- Hunt queries and results

## Possible false positives
- Old indicators reused by legitimate services
