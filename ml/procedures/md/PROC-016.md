---
id: PROC-016
title: "Malicious scheduled task or cron job"
tactic: Execution
techniques: [T1053.005, T1053.003]
severity: high
tags: [persistence, scheduled-task, cron]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-016 Malicious scheduled task or cron job

## Detection signals
- New task running from a user-writable path
- Task created remotely or by a non-admin tool
- Cron entry that downloads and runs a script

## Triage
- List tasks created recently and their actions
- Check the creator account and time
- Hash the referenced binary or script

## Containment
- Disable the task
- Isolate the host if the binary is malicious

## Eradication
- Delete the task and payload, hunt on other hosts for the same name

## Recovery
- Restore the host and audit task creation

## Evidence to keep
- Task XML, event 4698, crontab content, file hashes

## Possible false positives
- Software updaters and backup jobs
