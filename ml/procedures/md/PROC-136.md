---
id: PROC-136
title: "Containment decision framework (display-only in Sfumato)"
tactic: Response
techniques: []
severity: medium
tags: [containment, decision, sfumato]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-136 Containment decision framework (display-only in Sfumato)

## Detection signals
- A verdict recommends action

## Triage
- Weigh confidence, business impact and reversibility
- Prefer reversible actions first (block, disable, isolate)
- Require human approval for disruptive actions

## Containment
- Sfumato only recommends: it never blocks or modifies anything

## Eradication
- Not applicable

## Recovery
- Document the decision and who approved it

## Evidence to keep
- Decision record

## Possible false positives
- Not applicable
