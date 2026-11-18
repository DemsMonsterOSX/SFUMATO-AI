---
id: PROC-129
title: "PHP-CGI argument injection on Windows (CVE-2024-4577)"
tactic: Initial Access
techniques: [T1190]
severity: critical
tags: [cve, php, web, sfumato]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-129 PHP-CGI argument injection on Windows (CVE-2024-4577)

## Detection signals
- Requests to php-cgi with encoded soft hyphen and -d options
- Web server spawning PowerShell or cmd

## Triage
- Confirm PHP version and CGI mode on Windows
- Search logs for the encoded argument pattern
- Look for web shells and new accounts

## Containment
- Block the pattern at the WAF, isolate the server if execution is confirmed

## Eradication
- Upgrade PHP to a fixed version or switch away from CGI mode, remove implants

## Recovery
- Rebuild if compromise is confirmed, rotate secrets

## Evidence to keep
- Web logs, process tree, file timeline

## Possible false positives
- Vulnerability scanners probing the CVE
