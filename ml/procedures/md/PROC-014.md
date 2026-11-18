---
id: PROC-014
title: "User-executed malicious file"
tactic: Execution
techniques: [T1204.002]
severity: medium
tags: [user, malware, download]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-014 User-executed malicious file

## Detection signals
- Executable launched from Downloads, Temp or a mounted ISO
- Signed-looking installer with a rare publisher
- Endpoint prevents or quarantines a file after execution

## Triage
- Get the file hash and look it up
- Ask the user where it came from
- Check for second-stage downloads

## Containment
- Isolate the host if the sample is malicious
- Block the hash

## Eradication
- Remove the binary and its persistence

## Recovery
- Restore the host and reinforce application allow-listing

## Evidence to keep
- File copy, hash, execution timeline

## Possible false positives
- Legitimate software installed outside the managed catalogue
