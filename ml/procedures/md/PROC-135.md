---
id: PROC-135
title: "Disk and memory forensic acquisition"
tactic: Response
techniques: []
severity: medium
tags: [forensics, imaging]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-135 Disk and memory forensic acquisition

## Detection signals
- The incident manager requests an image

## Triage
- Capture memory first, then a disk image with a write blocker or cloud snapshot
- Hash the images

## Containment
- Isolate the system with the network cable or security group, not by shutdown

## Eradication
- Not applicable

## Recovery
- Store images read-only with access control

## Evidence to keep
- Hashes, acquisition log

## Possible false positives
- Not applicable
