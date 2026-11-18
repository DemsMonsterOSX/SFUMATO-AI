---
id: PROC-001
title: "Phishing e-mail with a malicious attachment"
tactic: Initial Access
techniques: [T1566.001]
severity: high
tags: [email, phishing, malware]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-001 Phishing e-mail with a malicious attachment

## Detection signals
- User reports an unexpected attachment (Office with macros, ISO, ZIP, HTML)
- Mail gateway flags the sender domain as new or look-alike
- Process tree: Office application spawns a script interpreter

## Triage
- Retrieve the original message headers and attachment hash
- Check who else received it (search mailboxes by sender, subject, hash)
- Look up the hash and sender domain in CTI
- Confirm whether the attachment was opened

## Containment
- Purge the message from all mailboxes
- Block sender domain and attachment hash at the gateway
- Isolate hosts where the attachment was executed

## Eradication
- Remove dropped files and persistence created after the open event
- Reset credentials of users who opened it

## Recovery
- Restore isolated hosts after a clean scan
- Send an awareness note with the indicators

## Evidence to keep
- Original .eml, attachment copy in a sandbox, mail gateway logs, endpoint process tree

## Possible false positives
- Legitimate bulk mailings from a partner that recently changed provider
