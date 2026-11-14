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

## Honest status and limits

* **Not yet executed on GCP.** The code compiles and the source listing was checked, but the Spark job has not run (Spark
  could not run locally on Windows without Hadoop native binaries). Run `smoke` first; expect to fix small issues before `run`.
  Results, timings and cost in the report must come from a real run: none are claimed here.
* Phase 3 (real-time) is **not implemented**; the brief makes it optional. A defensible option is to say that the data is
  bounded and historical, hence batch (CM2: "completeness and repeatability over latency").
* Binary classification only (attack vs benign). A time hold-out may show lower recall on attack families absent from the
  training days: report it as a finding, not as a defect.
* Link with the Sfumato application: the model is trained and evaluated here but **not yet served** to the SOAR playbook.
  Say so in the presentation, or add it as future work.
* Cost has not been measured. Check Billing after `run` and keep the budget alert.
