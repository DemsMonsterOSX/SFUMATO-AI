"""Stress producer: pushes pre-serialised flows to Kafka as fast as asked, for a fixed time (used by controller.py).

  python stress_producer.py --rate 2400 --seconds 30 --scenario known [--tag step3-p1]

Messages are built once (a few thousand rows turned into JSON bytes with a placeholder for the id) so that the Python producer
spends its time in librdkafka rather than in pandas; this is what lets one process reach several thousand messages per second.
Prints one JSON line at the end: {"sent": n, "errors": n, "seconds": s}.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import uuid

import pandas as pd

import common as c


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=float, required=True)
    ap.add_argument("--seconds", type=float, required=True)
    ap.add_argument("--scenario", default=c.SCENARIO)
    ap.add_argument("--tag", default="stress")
    a = ap.parse_args()
    df = pd.read_parquet(c.download(f"stream/replay/replay_{a.scenario}.parquet")).sample(n=4000, random_state=os.getpid() % 1000, replace=True)
    feats = [x for x in df.columns if x not in ("Label", "ts", "day", "is_attack")]
    prefix = f"{c.HOST}-{a.tag}-{uuid.uuid4().hex[:4]}"
    templates = []
    for _, row in df.iterrows():
        body = json.dumps({"id": "@@ID@@", "sent_at": 0.0, "scenario": a.scenario, "label": row["Label"], "stress": True,
                           "features": {f: (None if pd.isna(row[f]) else float(row[f])) for f in feats}})
        templates.append(body)
    prod = c.producer({"linger.ms": 5, "batch.num.messages": 2000, "queue.buffering.max.messages": 400000})
    sent = errors = 0

    def done(err, _m):
        nonlocal errors
        if err is not None:
            errors += 1

    t0 = time.time()
    i = 0
    while time.time() - t0 < a.seconds and not c.stop:
        tick = time.time()
        for _ in range(max(1, int(a.rate / 20))):   # twenty small batches per second
            mid = f"{prefix}-{i}"
            msg = templates[i % len(templates)].replace("@@ID@@", mid).replace('"sent_at": 0.0', f'"sent_at": {time.time():.3f}', 1)
            i += 1
            while True:
                try:
                    prod.produce(c.TOPIC_FLOWS, key=mid, value=msg, on_delivery=done)
                    break
                except BufferError:
                    prod.poll(0.05)
            sent += 1
        prod.poll(0)
        time.sleep(max(0.0, 0.05 - (time.time() - tick)))
    prod.flush(20)
    print(json.dumps({"sent": sent, "errors": errors, "seconds": round(time.time() - t0, 2)}), flush=True)


if __name__ == "__main__":
    main()
