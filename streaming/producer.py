"""Replay producer: publishes labelled network flows to Kafka at a controlled rate, as if they were captured live.

The replayed flows are NOT the ones the model was trained on: scenario "known" replays the 20 % held out from training,
scenario "unseen" replays the days after 2018-02-28 for a model trained before (attack families it has never seen).
The label travels with each message only so the scorer can measure itself; the model never reads it.
"""
from __future__ import annotations

import json
import time
import uuid

import pandas as pd

import common as c


def main() -> None:
    c.require_bucket()
    path = c.download(f"stream/replay/replay_{c.SCENARIO}.parquet")
    df = pd.read_parquet(path).sample(frac=1.0, random_state=int(time.time()) % 10000).reset_index(drop=True)
    feats = [x for x in df.columns if x not in ("Label", "ts", "day", "is_attack")]
    c.log(f"producer: scenario={c.SCENARIO} flows={len(df)} rate={c.RATE}/s bootstrap={c.BOOTSTRAP}")
    prod = c.producer()
    sent = errors = 0
    t0 = last_state = time.time()
    run = uuid.uuid4().hex[:6]

    def done(err, _msg):
        nonlocal errors
        if err is not None:
            errors += 1

    i = 0
    while not c.stop:
        tick = time.time()
        for _ in range(max(1, int(c.RATE / 10))):   # ten small batches per second keep the rate smooth
            row = df.iloc[i % len(df)]
            i += 1
            msg = {"id": f"{c.HOST}-{run}-{i}", "sent_at": time.time(), "scenario": c.SCENARIO, "label": row["Label"],
                   "features": {f: (None if pd.isna(row[f]) else float(row[f])) for f in feats}}
            while True:
                try:
                    prod.produce(c.TOPIC_FLOWS, key=msg["id"], value=json.dumps(msg), on_delivery=done)
                    break
                except BufferError:
                    prod.poll(0.1)
            sent += 1
        prod.poll(0)
        if time.time() - last_state > 5:
            c.write_state(f"producer-{c.HOST}", {"host": c.HOST, "scenario": c.SCENARIO, "target_rate": c.RATE, "sent": sent, "errors": errors,
                                                 "avg_rate": round(sent / max(time.time() - t0, 1), 1), "updated_at": time.time()})
            last_state = time.time()
        time.sleep(max(0.0, 0.1 - (time.time() - tick)))
    prod.flush(10)
    c.log("producer stopped, sent", sent)


if __name__ == "__main__":
    main()
