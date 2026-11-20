# Scalability and stress tests (measured 20 November 2026)

Raw results: `ml/scale/*.json`. Page in the dashboard: **Scalability** (`/scalability`, endpoint `bigdata/scalability`).
Scripts: `scripts/gcp_spark_scale.ps1`, `scripts/gcp_scale.ps1` + `streaming/scale_test.py`, `scripts/api_loadtest.py`.
Costs were not measured: read Billing.

## Summary

| Stage | What changes | Before → after | Reading |
|---|---|---|---|
| API (dashboard) | e2-micro (0.25 vCPU) → e2-medium (2 vCPU) | 15 → 181 req/s, p95 9.5 s → 0.54 s (64 connections, `/procedures?q=`) | CPU was the bottleneck: vertical scaling |
| Kafka scorers | 1 → 2 → 3 scorer VMs (e2-small Spot) | 9,546 → 17,865 → ≥ 23,834 flows/s | Near-linear: horizontal scaling |
| Spark (batch) | 2 → 3 → 4 executors (8 → 12 → 16 vCPU) | prep 738 s → 536 s → 416 s | Speed-up ×1.38 and ×1.77 (ideal ×1.5 and ×2) |
| Response cache on the API | no extra resource | no measured gain | kept, not claimed as an improvement |

## Spark executors

Same preparation job as the main run (read 10 CSV, clean, Parquet partitioned by day, aggregates), ML skipped, fixed number of
executors with dynamic allocation off, batches run one after the other. `prep_seconds` is written by the job; the batch wall time
also includes the serverless cluster start (about 2 minutes).

| Executors | vCPU | Preparation | Batch wall time | Speed-up vs 2 | Efficiency |
|---|---|---|---|---|---|
| 2 | 8 | 738 s | 863 s | 1.00 | 100 % |
| 3 | 12 | 536 s | 658 s | 1.38 | 92 % |
| 4 | 16 | 416 s | 537 s | 1.77 | 89 % |

For reference, the original full run (up to 8 executors, dynamic allocation) took 414 s for the same step. Limits found:
Dataproc Serverless refuses fewer than 2 executors; the project's global quota (about 32 vCPU) refused 4 executors while the Kafka,
Flink, ELK, Qwen and dashboard VMs were running (they were stopped for the 4-executor run), and 8 executors (36 vCPU) cannot run
without a quota increase. Each point is one run: no repetition, so no confidence interval.

## Kafka scorers (producers on a separate VM)

The first stress test ran its producers on kafka-1 next to a broker and a scorer: the producer was the limit and the result was
only a lower bound (4,078 to 6,472 flows/s). `streaming/scale_test.py` runs from `sfumato-qwen` (4 vCPU) with 3 to 6 producer
processes; the scorers are started and stopped through the metadata `stream-roles` (`scripts/gcp_scale.ps1 run`). A step passes
when the scorers consume at least 95 % of what is produced and the backlog stays under 3 s of traffic (30 s per step).

| Scorers | Highest rate kept up | First failing step |
|---|---|---|
| 1 | 9,546 flows/s | 12,000/s (backlog 26,840) |
| 2 | 17,865 flows/s | 21,000/s (backlog 32,400) |
| 3 | 23,834 flows/s | none: 24,000/s was the top target, producers on one VM (lower bound) |

Limits: 6 partitions mean at most 6 useful scorers; messages are pre-built from the labelled replay (not live traffic); the scorers
ship their logs to Logstash as in normal operation; one run per configuration; the 12,000/s step of the 2- and 3-scorer runs
comes from the first campaign, the higher steps from a second campaign with 6 producers.

## API load test

`scripts/api_loadtest.py` from this PC, through the Internet (about 138 ms round trip), HTTPS, Caddy, the Next.js proxy and FastAPI.
Results at 64 connections (before = e2-micro; medium = e2-medium):

| Route | before | medium |
|---|---|---|
| `/health` | 120 req/s, p95 0.68 s (collapse in the second run: 17 req/s) | 182 req/s, p95 0.53 s |
| `/procedures?q=ransomware` | 16 req/s, p95 9.6 s | 181 req/s, p95 0.54 s |
| `/bigdata/overview` | 10 req/s, p95 13 s | 133 req/s, p95 0.66 s |
| `/cves/summary` | 11 req/s at 32 connections, p95 5.4 s | 84 req/s, p95 1.0 s |

A 30–60 s response cache (`backend/app/core/ttlcache.py`) was added on the heavy read routes before the VM was resized; the test
after it showed no improvement on e2-micro, so the bottleneck is the CPU, not the route code. The dashboard VM was left on
e2-medium after the test (it costs more than e2-micro while running). The client machine and the shared network path may also limit
what is measured at the highest levels. `/cves/search` was not tested (it needs a `q` parameter).
