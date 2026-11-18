---
id: PROC-007
title: "Drive-by compromise through a web browser"
tactic: Initial Access
techniques: [T1189]
severity: medium
tags: [web, browser, exploit-kit]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-007 Drive-by compromise through a web browser

## Detection signals
- Browser spawns an unexpected child process after visiting a site
- Download of an executable from an ad network domain
- Proxy shows redirect chains to a landing page

## Triage
- Identify the URL chain and the browser version
- Check whether the browser or plug-ins were patched
- Look for payloads written to disk after the visit

## Containment
- Block the domains at the proxy
- Isolate the workstation if a payload executed

## Eradication
- Remove dropped files and persistence
- Update the browser and extensions

## Recovery
- Re-image the host if code execution is confirmed

## Evidence to keep
- Proxy logs, browser history, endpoint alerts, downloaded files

## Possible false positives
- Ad-blocker or security tool pages triggering a generic rule
