---
id: PROC-006
title: "Supply-chain compromise of a software dependency"
tactic: Initial Access
techniques: [T1195.002]
severity: high
tags: [supply-chain, dependency, build]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-006 Supply-chain compromise of a software dependency

## Detection signals
- Advisory about a malicious package or compromised update
- Unexpected network calls from a build or an application
- Hash of a deployed artefact differs from the published one

## Triage
- Inventory where the affected package and versions are used (SBOM, lockfiles)
- Compare hashes with the vendor-published values
- Check build logs for install scripts that ran

## Containment
- Pin or remove the affected version and block it in the registry proxy
- Rotate secrets available to the build environment

## Eradication
- Rebuild from clean sources with verified dependencies
- Hunt for persistence or callbacks created by the package

## Recovery
- Redeploy verified artefacts
- Add dependency pinning and signature verification

## Evidence to keep
- Lockfiles, build logs, artefact hashes, registry audit log

## Possible false positives
- Legitimate version bumps that changed install behaviour
