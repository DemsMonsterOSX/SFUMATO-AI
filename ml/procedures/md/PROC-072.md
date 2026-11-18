---
id: PROC-072
title: "Data staged and archived before exfiltration"
tactic: Collection
techniques: [T1560, T1005]
severity: medium
tags: [staging, archive, collection]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-072 Data staged and archived before exfiltration

## Detection signals
- Large archives (7z, rar, zip) in temp or public folders
- Mass file reads by one process

## Triage
- List the archive content and the source folders
- Check what left the network afterwards

## Containment
- Quarantine the archives and isolate the host

## Eradication
- Remove the archives and the tool used

## Recovery
- Review file-access permissions on the source data

## Evidence to keep
- File timeline, process logs

## Possible false positives
- Planned data migrations
