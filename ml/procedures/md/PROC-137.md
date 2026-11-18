---
id: PROC-137
title: "Machine-learning model drift and unseen attack families"
tactic: Analysis
techniques: []
severity: medium
tags: [ml, drift, sfumato, bigdata]
dataset_families: []
status: draft-generated-not-validated
---

# PROC-137 Machine-learning model drift and unseen attack families

## Detection signals
- Detection rate drops on new attack types or after infrastructure changes
- Time hold-out evaluation much worse than the random split

## Triage
- Compare recall per family on a time-based hold-out, not only on a random split
- Check whether the missed family exists in the training data
- Experiment note (CIC-IDS2018): recall 0.94 on a random split but 0.0005 on later days with unseen families

## Containment
- Use rate-based and signature rules next to the model for new behaviour

## Eradication
- Retrain with representative data and re-validate on a time split

## Recovery
- Monitor recall per family and alert on drift

## Evidence to keep
- Evaluation report, confusion matrices

## Possible false positives
- Not applicable
