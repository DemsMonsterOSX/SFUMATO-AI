# Big Data project: network intrusion detection at scale (Sfumato)

Semester project of *Cloud Data Structure* (Big Data Analysis using a dataset of choice). Sfumato is the SOC platform; this
module is its **data-engineering back end**: it processes a labelled dataset of **6.9 GB** on Google Cloud to learn what
malicious network traffic looks like.

## Problem and justification (rubric: Justification, Proposal)

A SOC receives millions of network flows per day; analysts cannot read them, and a single machine cannot even hold a few
days of them in memory. Question: **can distributed batch processing and ML separate attack flows from benign ones, and
does the model still work on days it has never seen?** Measurable objectives: (1) process the full 6.9 GB reproducibly,
(2) report data-quality losses, (3) reach a stated AUC-PR / recall on a random split **and** on a time hold-out, (4) publish
the figures in a dashboard.

Dataset: **CSE-CIC-IDS2018** (Canadian Institute for Cybersecurity + CSE), "Processed Traffic Data for ML Algorithms":
10 CSV files, 6.89 GB (measured from the source bucket listing), about 16 million flows with ~80 CICFlowMeter features and a
label (Benign, brute force, DoS, DDoS, botnet, web attacks, infiltration). Public on AWS Open Data, no account needed.
Why it fits: real captured traffic, strong class imbalance, variety of attacks, size that justifies a cluster
(one file alone is 4 GB). Credit the authors in the report and check their terms of use before publishing results.

## Course mapping (CM1-CM3)

| Course idea | Where it is in the project |
|---|---|
| Value chain: ingest, storage, processing, analytics (CM1) | `ingest.py` -> Cloud Storage -> Spark -> BigQuery -> `report.py` |
| 5 Vs (CM1) | Volume 6.9 GB; Variety: two CSV layouts (80 vs 84 columns); Veracity: repeated headers, `Infinity`, `NaN`, negative durations removed and counted; Velocity: batch only (see limits) |
| Batch processing, bounded dataset (CM2) | `spark_pipeline.py` on Dataproc Serverless |
| Object storage instead of HDFS, Dataproc (CM2) | Cloud Storage + Dataproc Serverless |
| Map / shuffle / reduce (CM2) | `groupBy` aggregations in the EDA step are the same pattern |
| Columnar format, partitioning (CM3) | clean data written as **Parquet partitioned by day** |
| SQL on a data lake, OLAP (CM3) | `queries.sql` in BigQuery over the same Parquet |
| Choose by access pattern, not by label (CM3) | files for raw data, Parquet+BigQuery for analytics, SQLite for Sfumato's operational incidents |

## Pipeline

```
AWS open bucket --ingest.py--> gs://BUCKET/bigdata/raw (10 CSV)
   --Spark (Dataproc Serverless)--> clean Parquet partitioned by day + results.json
   --bq load--> BigQuery dataset sfumato_bigdata.flows --queries.sql--> OLAP answers
   --report.py--> report/index.html (Chart.js dashboard)
```

Spark steps (`spark_pipeline.py`): read all CSVs as strings, `unionByName(allowMissingColumns)`, drop embedded header rows,
cast to double, turn `Infinity`/`NaN` into null and drop, parse timestamps (3 formats), drop negative durations, derive
`is_attack`, `day`, `hour`; write Parquet; EDA aggregates; Random Forest (60 trees, depth 12) trained on at most
`--train-rows` rows (default 2 M, so the cost stays bounded) and evaluated with AUC-ROC, **AUC-PR**, precision, recall, F1 and
the confusion matrix on (a) a random 80/20 split and (b) a **time hold-out** (train on the earlier 70 % of days, test on the
rest). Accuracy alone is not reported: classes are imbalanced.

## Reproduce

```powershell
gcloud auth login ; gcloud config set project <PROJECT_ID>        # billing must be linked
.\scripts\gcp_bigdata.ps1 setup      # APIs, Private Google Access, IAM
.\scripts\gcp_bigdata.ps1 ingest     # 6.9 GB into your bucket
.\scripts\gcp_bigdata.ps1 smoke      # validate the job on a fake 12k-row sample first
.\scripts\gcp_bigdata.ps1 run        # full dataset
.\scripts\gcp_bigdata.ps1 bq         # BigQuery load + SQL
.\scripts\gcp_bigdata.ps1 report     # bigdata\report\index.html
```

Defaults point at project `gen-lang-client-0426716352` and bucket `sfumato-soc-4ab8ab-artifacts` (`-Project`, `-Bucket`).
Every costly step asks for confirmation.

## Results of the real run (14 November 2026, Dataproc Serverless, batch `sfumato-full-11141454`)

Figures are in `ml/bigdata/results.json` (shown on the *Big Data Lab* page) and in BigQuery (`sfumato_bigdata.flows`).

* **Volume and quality:** 16,233,002 raw flows, 16,137,169 kept (95,833 dropped = 0.59 %: embedded headers, `Infinity`/`NaN`,
  negative durations). Spark total 851 s (cleaning + Parquet 414 s, ML 425 s). The BigQuery table has exactly 16,137,169 rows.
* **Class balance:** 83.0 % benign, 14 attack families; rarest: SQL Injection 87 flows, Brute Force-XSS 230.
* **Attacks are scheduled by day** (BigQuery query 2): 14 Feb FTP/SSH brute force, 15 Feb GoldenEye/Slowloris, 16 Feb
  Hulk/SlowHTTPTest, 20 Feb LOIC-HTTP, 21 Feb HOIC/LOIC-UDP, 22-23 Feb web attacks, 28 Feb-1 Mar infiltration, 2 Mar botnet.
* **Random Forest, random 80/20 split** (3,228,578 test flows): AUC-ROC 0.990, AUC-PR 0.980, precision 0.983, recall 0.941,
  F1 0.962 (TP 517,160, FP 8,840, FN 32,214, TN 2,670,364).
* **Random Forest, time hold-out** (train before 28 Feb, test from 28 Feb; 1,979,608 flows): AUC-ROC 0.710, AUC-PR 0.479,
  **recall 0.0005** (TP 244, FN 446,586). **The model does not detect attack families it has never seen** (infiltration and
  botnet appear only in the test days). The random split overstates real-world performance because every family is in the
  training set. This is the main finding to present, and the motivation for the unseen-family analysis below.

## Honest status and limits

* **Hour-of-day analysis is unreliable.** Timestamps only cover hours 1-12 in the source files (likely a 12-hour clock
  without AM/PM). Do not draw conclusions from the "by hour" chart; day-level analysis is sound.
* The label `Infilteration` is the dataset's own spelling.
* Cost of the run has still not been read from Billing: check it before quoting any figure.
* Phase 3 (real-time) is **not implemented**; the brief makes it optional. A defensible option is to say that the data is
  bounded and historical, hence batch (CM2: "completeness and repeatability over latency").
* Binary classification only (attack vs benign). A time hold-out may show lower recall on attack families absent from the
  training days: report it as a finding, not as a defect.
* Link with the Sfumato application: the model is trained and evaluated here but **not yet served** to the SOAR playbook.
  Say so in the presentation, or add it as future work.
* Cost has not been measured. Check Billing after `run` and keep the budget alert.
