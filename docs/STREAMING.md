# Distributed data streaming and ingestion

Requirement from the team: a SOC works on a continuous flow, so if one VM crashes or is overloaded the pipeline must not stop. This
module puts the flow on a **Kafka cluster of three brokers** with consumers that share the work, and ingests the vulnerability
feed hourly in a serverless job.

```
CVE feeds (CISA KEV, NVD, EPSS) --Cloud Scheduler hourly--> Cloud Run Job --> gs://BUCKET/cve/latest/ (summary, events)
                                                                              |
                                              cve-bridge (publishes the run's changes) --> topic cve-events --> cve-consumer
replay of held-out flows --> producer --> topic network-flows (6 partitions, replication 3)
                                              |--> scorer on kafka-1 (partitions 0,1)
                                              |--> scorer on kafka-2 (partitions 2,3)   consumer group "scorers-<scenario>"
                                              `--> scorer on kafka-3 (partitions 4,5)
                                                   |--> topic alerts      |--> topic network-flows-dlq (unparseable messages)
                                                   `--> state files gs://BUCKET/stream/state/*.json --> web app "Live Stream" page
```

## Components

| Piece | Where | Role |
|---|---|---|
| Kafka 4.1.2, KRaft (no ZooKeeper) | 3 Spot VMs `sfumato-kafka-1..3` (e2-small) | each node is broker and controller; replication 3, min in-sync replicas 2 |
| `streaming/producer.py` | kafka-1 | replays labelled flows at a controlled rate (acks=all, idempotent) |
| `streaming/scorer.py` | kafka-1, -2, -3 | consumer group: classifies each flow, publishes alerts, commits offsets after delivery (at-least-once), dead-letter topic |
| `streaming/cve_bridge.py` / `cve_consumer.py` | kafka-1 / kafka-2 | CVE changes of each hourly run become events on `cve-events` |
| `bigdata/cve_job/` + `scripts/gcp_cve_job.ps1` | Cloud Run Job + Cloud Scheduler | hourly incremental ingestion (only what changed), writes the bucket |
| `deploy/stream/kafka-startup.sh` | VM startup script | installs Kafka (SHA-512 verified), runs it as a service, installs a 30-second sync timer |

The applications are not copied to the VMs by hand: the sync timer on each VM polls `gs://BUCKET/stream/code/manifest.json`,
installs the code when its sha256 changes (verified), and starts or stops each service according to the instance metadata
`stream-roles` and `stream-env`. No SSH is needed.

## Run it

```powershell
.\scripts\gcp_stream.ps1 up                                  # 3 Spot VMs, brokers and topics (first time: about 6 minutes)
python streaming/train_model.py --sample <exported parquet> --out streaming/model   # only to rebuild the models
.\scripts\gcp_stream.ps1 deploy-app                          # code, models and replay data to the bucket
.\scripts\gcp_stream.ps1 run -Scenario known -Rate 300       # or -Scenario unseen
.\scripts\gcp_stream.ps1 halt                                # stop the applications (brokers stay up)
.\scripts\gcp_stream.ps1 stop                                # stop the three VMs (nothing billed for compute)
.\scripts\gcp_stream.ps1 start                               # start them again; Kafka restarts by itself
.\scripts\gcp_stream.ps1 teardown                            # delete the VMs and their disks
.\scripts\gcp_cve_job.ps1 deploy | run | status | pause      # hourly CVE ingestion
```

The data come from `streaming/sample_export.sql` (a stratified sample of the 16 M flows: up to 20,000 per attack family and
120,000 benign flows). The web app page **Live Stream** shows the live state while the applications run.

## What was measured (19 November 2026)

| Scenario | What is replayed | Flows | Precision | Recall |
|---|---|---|---|---|
| known | 20 % of the sample held out from training, model trained on the other 80 % | 71,485 | 0.9895 | 0.9319 |
| unseen | days from 2018-02-28 on, model trained before (Infilteration and Bot never seen) | 46,097 | 0.619 | **0.0015** |

Both agree with the offline evaluation (0.9898 / 0.9303 and 0.5876 / 0.0014). **The stream does not make the model generalise**: it
detects 93 % of attacks it has learned and almost none of the families it never saw (botnet: 0 of 17,113 flows flagged).
The sample is not natural traffic (about 62 % attacks), so precision and recall describe this mix.

**Failure test.** While 300 flows/s were flowing, `sfumato-kafka-3` (one broker and one scorer) was stopped: producer errors 0, the two
remaining scorers took over the six partitions (0-1-2 and 3-4-5) and kept consuming; after the restart the VM rejoined the
group (partitions 4-5) and the lag of the three scorers fell to about 15-20 messages each.

Results file: `ml/stream/results.json`.

## Cost and budget

Estimates from public prices as I know them, **not verified in the pricing calculator and not read from Billing**:

* three e2-small Spot VMs: roughly 0.02-0.03 USD per hour together while running, nothing for compute when stopped;
* each scorer, producer and consumer writes a small state file every 5-10 seconds: running the five processes for a day makes
  roughly 85,000 object writes, which is a few tens of cents per day in storage operations. **Run the streaming only during tests and
  demos** (`halt` when finished);
* Cloud Run job, Cloud Scheduler and Cloud Build for the hourly CVE job: inside the free tiers according to the published limits.

## Limits and honest notes

* **Not 24/7.** The cluster is started for tests and demos. A permanently running SOC would need monitoring, alerting, security
  and a budget this project does not have.
* **Spot VMs** can be reclaimed by Google at any time. Replication 3 tolerates the loss of one broker; two at once would stop writes.
* **Security:** the brokers use plain-text listeners without authentication. They are reachable only from the project's internal
  network (no firewall rule opens 9092/9093 to the Internet), but the default network allows every VM of the project to reach them.
  SSH (port 22) is open to the Internet by Google's default rule, as on any new project.
* Only one failure scenario (one broker) was tested. No audit of exactly-once delivery was done: processing is at-least-once and a
  failover can score a few flows twice.
* The CVE bridge publishes the changes of each hourly run; it does not guarantee that a run was published exactly once if the
  bucket state write fails between publishing and recording.
* The tested rate was 300 flows/s; that is not a measured maximum.
* Kafka's SHA-512 is read from Apache's download site (the same origin as the file); the signature (.asc) was not checked.
