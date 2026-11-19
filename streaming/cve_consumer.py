"""CVE event consumer: reads cve-events and keeps live counters and the latest events for the web app.

Writes gs://BUCKET/stream/state/cve-consumer.json. Offsets are committed after each batch (at-least-once): a restart may count
a few events twice, which the page presents as an approximate live counter, not as an inventory.
"""
from __future__ import annotations

import json
import time
from collections import Counter, deque

import common as c


def main() -> None:
    c.require_bucket()
    cons = c.consumer("cve-consumers", {"auto.offset.reset": "earliest"})
    cons.subscribe([c.TOPIC_CVE])
    counts, recent = Counter(), deque(maxlen=40)
    total = 0
    last_state = time.time()
    c.log("cve-consumer started")
    while not c.stop:
        msgs = cons.consume(num_messages=200, timeout=1.0)
        n = 0
        for m in msgs:
            if m.error():
                continue
            try:
                ev = json.loads(m.value())
            except Exception:  # noqa: BLE001
                continue
            counts[ev.get("type", "unknown")] += 1
            if ev.get("severity"):
                counts[f"severity_{ev['severity']}"] += 1
            if ev.get("kev"):
                counts["kev"] += 1
            recent.appendleft({k: ev.get(k) for k in ("type", "id", "severity", "kev", "published", "run")})
            n += 1
        if n:
            total += n
            cons.commit(asynchronous=False)
        if time.time() - last_state > 10:
            c.write_state("cve-consumer", {"host": c.HOST, "events_consumed": total, "counts": dict(counts), "recent": list(recent), "updated_at": time.time()})
            last_state = time.time()
    cons.close()


if __name__ == "__main__":
    main()
