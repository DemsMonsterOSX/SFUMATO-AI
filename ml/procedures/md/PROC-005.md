---
id: PROC-005
title: "Exposed remote access service (RDP, VPN, SSH)"
tactic: Initial Access
techniques: [T1133]
severity: high
tags: [remote-access, exposure]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-005 Exposed remote access service (RDP, VPN, SSH)

## Detection signals
- Internet scan shows RDP 3389 or SSH 22 open to the world
- Many authentication attempts from unrelated IPs
- Login from a host that is not a known jump server

## Triage
- Confirm exposure with an external scan
- Review successful logins in the exposure window
- Check the host for new local accounts and tools

## Containment
- Close the port or restrict to a VPN or allow-list
- Reset passwords of accounts that logged in remotely

## Eradication
- Enforce MFA and network-level authentication, patch the service

## Recovery
- Monitor for retries after closing exposure
- Document the approved remote access path

## Evidence to keep
- Firewall rules, service authentication logs, scan result

## Possible false positives
- Approved vendor access windows
