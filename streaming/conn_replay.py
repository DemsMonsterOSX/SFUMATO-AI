"""Replay Zeek connection records into Kafka (topic conn-events) in event-time order, as fast as the brokers allow.

  python conn_replay.py --days 2018-02-14 2018-02-15 --bucket sfumato-soc-4ab8ab-artifacts --partitions 6 [--max-rate 0]

Reads gs://BUCKET/bigdata/pcap/<day>/conn/out/*.parquet (written by deploy/pcap/pcap-startup.sh), labels every connection with the family of
the attacker host and slot of bigdata/pcap_labels.json (a label used only to measure the rules, never by them), sorts a day by time and
publishes key = source address so that all the records of a source stay in one partition (the key of the Flink state). Prints one JSON line
per day: records, seconds, records per second. Run it on a VM whose service account can read the bucket.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import time

import pandas as pd

TOPICS = {"conn-events": None, "source-alerts": None, "naive-alerts": None}


def ensure_topics(bootstrap: str, partitions: int) -> None:
    from confluent_kafka.admin import AdminClient, NewTopic
    adm = AdminClient({"bootstrap.servers": bootstrap})
    have = set(adm.list_topics(timeout=20).topics)
    new = [NewTopic(t, num_partitions=partitions, replication_factor=3, config={"min.insync.replicas": "2"}) for t in TOPICS if t not in have]
    for t, f in adm.create_topics(new).items():
        f.result()
        print("created topic", t, flush=True)


def load_day(day: str, bucket: str, labels: dict, tmp: str) -> pd.DataFrame:
    from google.cloud import storage
    cl = storage.Client()
    parts = []
    for b in cl.list_blobs(bucket, prefix=f"bigdata/pcap/{day}/conn/out/"):
        if b.name.endswith(".parquet"):
            p = os.path.join(tmp, os.path.basename(b.name)); b.download_to_filename(p)
            parts.append(pd.read_parquet(p, columns=["ts", "id.orig_h", "id.resp_h", "id.resp_p"]))
            os.remove(p)
    df = pd.concat(parts, ignore_index=True).rename(columns={"id.orig_h": "src", "id.resp_h": "dst", "id.resp_p": "dport"})
    df["family"] = "benign"
    from datetime import datetime, timedelta, timezone
    off, margin = timedelta(hours=labels["utc_offset_hours"]), timedelta(minutes=labels["margin_minutes"])
    d0 = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    for att in labels["days"][day]["attacks"]:
        h0, m0 = map(int, att["start"].split(":")); h1, m1 = map(int, att["end"].split(":"))
        t0 = (d0 + timedelta(hours=h0, minutes=m0) + off - margin).timestamp(); t1 = (d0 + timedelta(hours=h1, minutes=m1) + off + margin).timestamp()
        df.loc[df["src"].isin(att["ips"]) & (df["ts"] >= t0) & (df["ts"] <= t1), "family"] = att["family"]
    return df.sort_values("ts", kind="stable").reset_index(drop=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", nargs="+", required=True)
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--bootstrap", default=os.environ.get("BOOTSTRAP", "sfumato-kafka-1.us-central1-a.c.gen-lang-client-0426716352.internal:9092,"
                    "sfumato-kafka-2.us-central1-a.c.gen-lang-client-0426716352.internal:9092,sfumato-kafka-3.us-central1-a.c.gen-lang-client-0426716352.internal:9092"))
    ap.add_argument("--partitions", type=int, default=6)
    ap.add_argument("--max-rate", type=float, default=0, help="records per second, 0 = as fast as possible")
    ap.add_argument("--labels", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bigdata", "pcap_labels.json"))
    a = ap.parse_args()
    from confluent_kafka import Producer
    ensure_topics(a.bootstrap, a.partitions)
    labels = json.load(open(a.labels, encoding="utf-8"))
    prod = Producer({"bootstrap.servers": a.bootstrap, "acks": "all", "enable.idempotence": True, "linger.ms": 20, "batch.num.messages": 5000,
                     "queue.buffering.max.messages": 1_000_000, "compression.type": "lz4"})
    errors = 0

    def cb(err, _m):
        nonlocal errors
        if err is not None:
            errors += 1

    total = 0
    with tempfile.TemporaryDirectory() as tmp:
        for day in a.days:
            df = load_day(day, a.bucket, labels, tmp)
            msgs = [(s, f'{{"src":"{s}","dst":"{d}","dport":{int(p)},"ts_s":{t:.3f},"family":"{f}"}}')
                    for s, d, p, t, f in zip(df["src"], df["dst"], df["dport"].fillna(0), df["ts"], df["family"])]
            t0 = time.time(); sent = 0
            for key, val in msgs:
                while True:
                    try:
                        prod.produce("conn-events", key=key, value=val, on_delivery=cb); break
                    except BufferError:
                        prod.poll(0.05)
                sent += 1
                if sent % 2000 == 0:
                    prod.poll(0)
                    if a.max_rate:
                        ahead = sent / a.max_rate - (time.time() - t0)
                        if ahead > 0:
                            time.sleep(ahead)
            prod.flush(120)
            dt = time.time() - t0; total += sent
            print(json.dumps({"day": day, "records": sent, "seconds": round(dt, 1), "records_per_s": round(sent / dt), "errors": errors}), flush=True)
    print(json.dumps({"total_records": total, "errors": errors}), flush=True)


if __name__ == "__main__":
    main()
