---
id: PROC-112
title: "SQL injection (family SQL Injection)"
tactic: Initial Access
techniques: [T1190]
severity: high
tags: [dataset, web, sqli]
dataset_families: [SQL Injection]
status: draft-generated-not-validated
---

# PROC-112 SQL injection (family SQL Injection)

## Detection signals
- Quotes, UNION SELECT, sleep() or comments in parameters
- Database errors in responses

## Triage
- Review queries and error logs
- Experiment note: only 31 test flows, multiclass recall 0.00: such rare attacks need signature or WAF rules, not this model

## Containment
- Block the pattern at the WAF, restrict database privileges

## Eradication
- Use parameterised queries and patch the code

## Recovery
- Check whether data was read or modified

## Evidence to keep
- Web logs, database audit logs

## Possible false positives
- Security scanners run by the team
