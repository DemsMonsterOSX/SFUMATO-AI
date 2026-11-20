"""Scalability test of the scoring pipeline, run from a dedicated load-generator VM (not from the Kafka brokers).

  python scale_test.py --bootstrap sfumato-kafka-1...:9092,... --parquet replay_known.parquet --label scorers=2 \
      --targets 600,1200,2400,4800,7200,9600 --step-seconds 30 --producers 3 --json out.json

Why a separate script: the first stress test (controller.py) ran its producers on kafka-1 next to a broker, a scorer and the controller,
so the producer was the limit and the result was only a lower bound. Here the producers run on another VM with more vCPUs.
For each target rate, N producer processes send pre-serialised flows (same message format as producer.py) for step-seconds while the
offsets of the topic network-flows are read: produced/s (end offsets), consumed/s (committed offsets of the scorer group) and the backlog.
The test does not start or stop scorers: set their number beforehand (metadata stream-roles on the Kafka VMs) and give it a label.
A step is "kept up" when consumed >= 95 % of produced and the end backlog is below 3 s of traffic. It stops at the first step where the
scorers fall behind (the number found is then a ceiling of the scorers) or when the producers cannot reach the target (a floor).
"""
from __future__ import annotations

import argparse
import json
import math
import multiprocessing as mp
import time
import uuid

TOPIC = "network-flows"


def build_templates(parquet: str, scenario: str, n: int = 4000) -> list[str]:
    import pandas as pd
    df = pd.read_parquet(parquet).sample(n=n, random_state=7, replace=True)
    feats = [x for x in df.columns if x not in ("Label", "ts", "day", "is_attack")]
    out = []
    for _, row in df.iterrows():
        out.append(json.dumps({"id": "@@ID@@", "sent_at": 0.0, "scenario": scenario, "label": row["Label"], "stress": True,
                               "features": {f: (None if pd.isna(row[f]) else float(row[f])) for f in feats}}))
    return out


def producer_proc(bootstrap: str, templates: list[str], rate: float, seconds: float, tag: str, q) -> None:
    from confluent_kafka import Producer
    prod = Producer({"bootstrap.servers": bootstrap, "linger.ms": 5, "batch.num.messages": 2000, "queue.buffering.max.messages": 400000,
                     "acks": "all", "enable.idempotence": True, "compression.type": "lz4"})
    errors = 0

    def done(err, _m):
        nonlocal errors
        if err is not None:
            errors += 1

    prefix = f"{tag}-{uuid.uuid4().hex[:4]}"
    sent, i, t0 = 0, 0, time.time()
    while time.time() - t0 < seconds:
        tick = time.time()
        for _ in range(max(1, int(rate / 20))):
            mid = f"{prefix}-{i}"
            msg = templates[i % len(templates)].replace("@@ID@@", mid).replace('"sent_at": 0.0', f'"sent_at": {time.time():.3f}', 1)
            i += 1
            while True:
                try:
                    prod.produce(TOPIC, key=mid, value=msg, on_delivery=done)
                    break
                except BufferError:
                    prod.poll(0.05)
            sent += 1
        prod.poll(0)
        time.sleep(max(0.0, 0.05 - (time.time() - tick)))
    prod.flush(30)
    q.put({"sent": sent, "errors": errors})


def offsets(bootstrap: str, group: str) -> tuple[int, int, int]:
    from confluent_kafka import Consumer, TopicPartition
    cons = Consumer({"bootstrap.servers": bootstrap, "group.id": group, "enable.auto.commit": False})
    try:
        md = cons.list_topics(TOPIC, timeout=10).topics[TOPIC]
        tps = [TopicPartition(TOPIC, p) for p in md.partitions]
        end = committed = 0
        for tp, com in zip(tps, cons.committed(tps, timeout=10)):
            lo, hi = cons.get_watermark_offsets(tp, timeout=10, cached=False)
            end += hi
            committed += com.offset if com.offset >= 0 else lo
        return end, committed, end - committed
    finally:
        cons.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", required=True)
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--scenario", default="known")
    ap.add_argument("--group", default="scorers-known")
    ap.add_argument("--label", default="")
    ap.add_argument("--targets", default="600,1200,2400,4800,7200,9600")
    ap.add_argument("--step-seconds", type=int, default=30)
    ap.add_argument("--producers", type=int, default=3, help="producer processes (a Python producer reaches about 2,500 msg/s each)")
    ap.add_argument("--json")
    a = ap.parse_args()
    templates = build_templates(a.parquet, a.scenario)
    print(f"[{a.label}] templates ready", flush=True)
    t_w = time.time()
    while time.time() - t_w < 90 and offsets(a.bootstrap, a.group)[2] > 500:   # empty backlog before the first step
        time.sleep(3)
    rows, best, ceiling = [], 0, "highest target reached"
    for target in [int(x) for x in a.targets.split(",")]:
        n = max(1, min(a.producers, math.ceil(target / 2500)))
        e0, k0, _ = offsets(a.bootstrap, a.group)
        q: mp.Queue = mp.Queue()
        t0 = time.time()
        procs = [mp.Process(target=producer_proc, args=(a.bootstrap, templates, target / n, a.step_seconds, f"sc{target}p{i}", q)) for i in range(n)]
        [p.start() for p in procs]
        [p.join() for p in procs]
        res = [q.get() for _ in procs]
        dt = time.time() - t0
        e1, k1, lag = offsets(a.bootstrap, a.group)
        produced, consumed = (e1 - e0) / dt, (k1 - k0) / dt
        errors = sum(r["errors"] for r in res)
        kept_up = errors == 0 and consumed >= 0.95 * max(produced, 1) and lag <= 3 * max(produced, 1)
        producer_limited = produced < 0.9 * target
        row = {"label": a.label, "target": target, "producers": n, "produced_per_s": round(produced), "consumed_per_s": round(consumed),
               "lag_end": lag, "errors": errors, "kept_up": kept_up, "producer_limited": producer_limited}
        rows.append(row)
        print(json.dumps(row), flush=True)
        if kept_up:
            best = max(best, round(consumed))
        else:
            ceiling = "scorers fell behind"
            break
        if producer_limited:
            ceiling = "producers (lower bound)"
            break
        t1 = time.time()
        while offsets(a.bootstrap, a.group)[2] > 100 and time.time() - t1 < 60:
            time.sleep(3)
    out = {"label": a.label, "steps": rows, "max_kept_up_per_s": best, "ceiling": ceiling, "step_seconds": a.step_seconds,
           "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    print(json.dumps(out), flush=True)
    if a.json:
        open(a.json, "w").write(json.dumps(out, indent=1))


if __name__ == "__main__":
    mp.set_start_method("fork")
    main()
