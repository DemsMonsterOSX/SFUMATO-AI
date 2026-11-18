---
id: PROC-008
title: "Malware introduced from removable media"
tactic: Initial Access
techniques: [T1091]
severity: medium
tags: [usb, removable-media, worm]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-008 Malware introduced from removable media

## Detection signals
- USB device first seen on a server or an air-gapped host
- autorun.inf or LNK files at the root of a drive
- Host starts scanning internal ranges after a device is inserted

## Triage
- Identify the device serial and the user
- Scan the device in an isolated station
- Check other hosts the device was connected to

## Containment
- Disable removable media on the affected hosts
- Isolate infected machines

## Eradication
- Remove the malware and shortcuts from affected hosts and the media

## Recovery
- Restore hosts and re-enable media with a device-control policy

## Evidence to keep
- Device registry entries, endpoint logs, copy of the media content

## Possible false positives
- Approved installer USB keys used by IT
