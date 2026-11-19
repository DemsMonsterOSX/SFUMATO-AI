"""Flow scorer: a Kafka consumer-group member that classifies each flow (attack vs benign) and publishes alerts.

Run on several VMs, the members of the group "scorers-<scenario>" share the 6 partitions of network-flows: add a member and the
partitions are rebalanced, kill one and its partitions move to the others. Offsets are committed only after the alerts of a batch
were delivered (at-least-once); a message that cannot be parsed goes to the dead-letter topic.
Its counters (confusion matrix against the replay labels, per family, latency, consumer lag) are written to
gs://BUCKET/stream/state/scorer-<host>.json for the web app.
"""
from __future__ import annotations

import json
import time
from collections import Counter, deque

import joblib
import numpy as np

import common as c


def lag(cons) -> dict:
    out = {}
    try:
        parts = cons.assignment()
        for tp, committed in zip(parts, cons.committed(parts, timeout=5)):
            lo, hi = cons.get_watermark_offsets(tp, timeout=5, cached=False)
            out[str(tp.partition)] = max(0, hi - (committed.offset if committed and committed.offset >= 0 else lo))
    except Exception:  # noqa: BLE001
        pass
    return out


def main() -> None:
    c.require_bucket()
    bundle = joblib.load(c.download(f"stream/model/model_{c.SCENARIO}.joblib"))
    model, feats = bundle["model"], bundle["features"]
    group = f"scorers-{c.SCENARIO}"
    cons, prod = c.consumer(group), c.producer()
    cons.subscribe([c.TOPIC_FLOWS])
    c.log(f"scorer: scenario={c.SCENARIO} group={group} threshold={c.THRESHOLD} features={len(feats)}")
    cm, per_label = Counter(), {}
    lat = deque(maxlen=2000)
    consumed = alerts = bad = 0
    t0 = last_state = time.time()
    window = deque(maxlen=12)   # (time, consumed) points for a throughput over about a minute
    while not c.stop:
        msgs = cons.consume(num_messages=500, timeout=1.0)
        good, rows, meta = [], [], []
        for m in msgs:
            if m.error():
                continue
            try:
                d = json.loads(m.value())
                rows.append([np.nan if d["features"].get(f) is None else d["features"][f] for f in feats])
                meta.append(d)
                good.append(m)
            except Exception:  # noqa: BLE001
                bad += 1
                prod.produce(c.TOPIC_DLQ, key=m.key(), value=m.value())
        if rows:
            p = model.predict_proba(np.array(rows, dtype="float64"))[:, 1]
            now = time.time()
            for d, pr in zip(meta, p):
                is_attack = d["label"] != "Benign"
                flagged = pr >= c.THRESHOLD
                cm[("tp" if flagged else "fn") if is_attack else ("fp" if flagged else "tn")] += 1
                lab = per_label.setdefault(d["label"], [0, 0])
                lab[0] += 1
                lab[1] += int(flagged)
                lat.append((now - d["sent_at"]) * 1000)
                if flagged:
                    alerts += 1
                    prod.produce(c.TOPIC_ALERTS, key=d["id"], value=json.dumps(
                        {"id": d["id"], "p": round(float(pr), 4), "label": d["label"], "scenario": d["scenario"], "host": c.HOST,
                         "latency_ms": round((now - d["sent_at"]) * 1000, 1), "at": now}))
            consumed += len(rows)
            prod.flush(10)
            cons.commit(asynchronous=False)
        prod.poll(0)
        if time.time() - last_state > 5:
            window.append((time.time(), consumed))
            thr = (window[-1][1] - window[0][1]) / max(window[-1][0] - window[0][0], 1) if len(window) > 1 else 0.0
            c.write_state(f"scorer-{c.HOST}", {
                "host": c.HOST, "scenario": c.SCENARIO, "group": group, "consumed": consumed, "alerts": alerts, "dead_letters": bad,
                "confusion": dict(cm), "per_label": {k: {"flows": v[0], "flagged": v[1]} for k, v in per_label.items()},
                "throughput_per_s": round(thr, 1), "latency_ms": {"p50": c.percentile(list(lat), 0.5), "p95": c.percentile(list(lat), 0.95)},
                "lag_by_partition": lag(cons), "partitions": sorted(tp.partition for tp in cons.assignment()),
                "uptime_s": round(time.time() - t0), "updated_at": time.time()})
            last_state = time.time()
    cons.close()
    prod.flush(10)
    c.log("scorer stopped, consumed", consumed)


if __name__ == "__main__":
    main()
