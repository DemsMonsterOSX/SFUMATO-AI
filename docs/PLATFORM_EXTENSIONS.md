# Platform extensions: internal Qwen, Flink, ELK logs, API console

All of these run on demand on small GCP VMs (start them, use them, stop them) to stay inside the project budget. Every VM below is
reachable from the project's internal network only; none of them has a firewall rule opening its ports to the Internet.

| Component | VM | Script | What it does |
|---|---|---|---|
| Internal Qwen | `sfumato-qwen` (e2-standard-4, 16 GB, Spot) | `scripts/gcp_qwen.ps1` | Ollama serving `qwen2.5:7b-instruct` for the Da Vinci AI agent |
| Apache Flink | `sfumato-flink` (e2-medium, Spot) | `scripts/gcp_flink.ps1` | stateful 10-second windows and rate rules on the Kafka flow |
| Logs (Elasticsearch + Logstash) | `sfumato-elk` (e2-standard-2, 8 GB, Spot) | `scripts/gcp_elk.ps1` | log indexing, **Logs** tab |
| Kafka | `sfumato-kafka-1..3` (e2-small, Spot) | `scripts/gcp_stream.ps1` | see `docs/STREAMING.md` |

## Da Vinci AI with the internal Qwen

* The agent answers in two steps: an **instant answer from deterministic rules** (exact figures from the published results,
  procedures, CVE feed, bucket listing, project documentation), then, when a language model is available, a **rewrite by the model** from
  the same data that replaces it. Without the model the rules answer stays.
* `DAVINCI_PROVIDER=ollama` selects the internal Qwen for the agent only (the SOAR investigator keeps its own provider); if Qwen is
  not reachable the global provider or the rules are used. The model receives a **short** context (the draft answer and at most two
  excerpts): a 7B model on CPU cannot read the full result files in a useful time.
* Retrieval: BM25 over the response procedures (`ml/procedures`) and over the project documentation (`README.md`, `docs/*.md`), with a small
  French-to-English hint table. Bucket contents are listed through the same allow-listed dataset service as the API console.
* **Measured** on `e2-standard-4`: 5.5 generated tokens per second, model load 4.7 s; an agent answer took **32 to 78 seconds**. That is
  why the rules answer is shown first. A larger VM would be faster at a higher hourly cost (not measured).
* Quality: the four test questions were answered in French, grounded in the data, with the "unvalidated draft" warning for procedures. Not
  evaluated at scale; a 7B model can still blend two sources (one answer mixed the Kafka cluster with the CVE job).
* Licence: Qwen2.5-7B-Instruct is published under the Apache 2.0 licence. The 3B model uses a research licence and was not used.

## Flink

A standalone Flink 1.20.5 (one JobManager, one TaskManager with 2 slots) runs two Flink SQL jobs on the topic `network-flows`:

* `flow-aggregates`: tumbling 10-second event-time windows (flows, attack flows from the replay labels, distinct ports, mean duration, SYN flows);
* `rule-alerts`: per-port bursts of at least 200 flows shorter than one second in 10 s (brute force on 21/22, HTTP flood on 80/443/8080), DNS excluded.

The rules need no model, so they see families the model never learned. **Measured** (known-families replay, 300 flows/s): bursts on
ports 21, 22 and 80 were flagged, with **90 % of the flows in the alerted windows being attacks** according to the replay labels (the rules
never read the labels). Caveat: the replay is 62 % attacks; on real traffic a burst of short flows on port 80 is mostly legitimate and these
rules would need source addresses and history to be usable. The CIC flow records exported for the replay carry no addresses.

Bugs found and fixed while building it (kept here because they are instructive): a second job stays `CREATED` forever when the first one
takes every task slot (parallelism 1 per job fixed it); a trailing comment after a `SET` statement broke the script while the SQL client
still exited with status 0 (the startup script now counts the running jobs and prints the client log otherwise).

## Logs (ELK without Kibana)

Elasticsearch 8.x and Logstash 8.x on one 8 GB VM. Applications push events over HTTP (`app/core/logship.py`, `streaming/logship.py`:
queued, batched, dropped silently when Logstash is unreachable so a log problem never slows a request) to Logstash port 8080 (basic auth);
Logstash indexes them in `sfumato-logs-YYYY.MM.dd` (14-day retention). The **Logs** tab queries Elasticsearch through the API
(`/api/v1/logs/status|overview|search`): volume by level, busiest routes with latency, errors and a full-text search.

Limits: Kibana is not deployed (1 GB more memory, and it would need exposing a service); only application logs are collected (API requests
and warnings, streaming applications), not system logs; plain HTTP and one password inside the project network (no TLS); events sent while the
VM is off are lost; a single node without replicas.

## API console

The **API Console** page calls the platform API from the browser through the team login: create an incident (same endpoint as the
simulator), fetch one CVE live (NVD + KEV + EPSS, rate-protected), browse the bucket datasets (allow-listed prefixes, previews of CSV files read with
a 256 KB byte range, even for the 4 GB files), see the API's own load, the partitions shared by the Kafka scorers and run a requests-per-second test.

* The API limits each key to **120 requests per minute by default**, and the dashboard proxy uses one key for the whole team: the VM now runs with
  6,000 per minute. `/health` is never limited.
* **Measured** from a workstation through HTTPS, Caddy, the Next.js proxy and the API on the 0.25-vCPU VM: about **40 requests per second** on `/health`
  (the lightest route), saturating at 8 to 16 connections. That is a property of the small VM, not of the code.
* `scripts/api_loadtest.py` repeats this measurement from the command line.
* The stress test of the streaming pipeline (button on the Live Stream page) is a different measurement: see `docs/STREAMING.md`.

## Cost control

Everything above is started and stopped on demand. Estimates from public prices, not verified in the calculator and not read from Billing:
a few cents per hour per VM while running, nothing for compute while stopped (disks are still billed). Always stop the VMs when a session ends:

```powershell
.\scripts\gcp_stream.ps1 halt ; .\scripts\gcp_stream.ps1 stop
.\scripts\gcp_flink.ps1 stop ; .\scripts\gcp_qwen.ps1 stop ; .\scripts\gcp_elk.ps1 stop
```
