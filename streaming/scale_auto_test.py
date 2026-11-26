"""Autoscaling test: a constant overload that the 3 scorers of the Kafka VMs cannot absorb, from the load-generator VM.

  python scale_auto_test.py --bootstrap HOST:9092,... --parquet replay_known.parquet --rate 32000 --seconds 300 --producers 8 --json out.json

The producers send --rate flows/s for --seconds while this process samples, every 5 s, the end offsets, the committed offsets of the scorer
group and the backlog of the topic network-flows. After the producers stop, it keeps sampling until the backlog is drained (or --drain-max s).
The autoscaler (streaming/autoscaler.py, in the controller on kafka-1) must be running: the output is a timeline of produced/s, consumed/s
and lag, from which the scale-out moments and the recovery are read next to the autoscaler's own events.
It starts nothing and stops nothing: no scorer is touched by this script.
"""
from __future__ import annotations

import argparse
import json
import math
import multiprocessing as mp
import time

import scale_test as st


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", required=True)
    ap.add_argument("--parquet", required=True)
    ap.add_argument("--scenario", default="known")
    ap.add_argument("--group", default="scorers-known")
    ap.add_argument("--rate", type=int, default=32000)
    ap.add_argument("--seconds", type=int, default=300)
    ap.add_argument("--producers", type=int, default=8)
    ap.add_argument("--drain-max", type=int, default=240)
    ap.add_argument("--json")
    a = ap.parse_args()
    templates = st.build_templates(a.parquet, a.scenario)
    t_w = time.time()
    while time.time() - t_w < 90 and st.offsets(a.bootstrap, a.group)[2] > 500:
        time.sleep(3)
    n = max(1, min(a.producers, math.ceil(a.rate / 2500)))
    q: mp.Queue = mp.Queue()
    procs = [mp.Process(target=st.producer_proc, args=(a.bootstrap, templates, a.rate / n, a.seconds, f"au{i}", q)) for i in range(n)]
    e0, k0, _ = st.offsets(a.bootstrap, a.group)
    t0 = time.time()
    [p.start() for p in procs]
    print(f"producing {a.rate}/s with {n} processes for {a.seconds} s", flush=True)
    timeline, prev = [], (t0, e0, k0)
    producing_until = t0 + a.seconds
    while True:
        time.sleep(5)
        now = time.time()
        e, k, lag = st.offsets(a.bootstrap, a.group)
        dt = max(now - prev[0], 1e-6)
        row = {"t": round(now - t0), "produced_per_s": round((e - prev[1]) / dt), "consumed_per_s": round((k - prev[2]) / dt), "lag": lag, "producing": now < producing_until}
        timeline.append(row)
        print(json.dumps(row), flush=True)
        prev = (now, e, k)
        if now > producing_until and (lag < 200 or now > producing_until + a.drain_max):
            break
    [p.join(timeout=60) for p in procs]
    res = [q.get() for _ in procs if not q.empty()]
    out = {"rate_target": a.rate, "seconds": a.seconds, "producers": n, "errors": sum(r["errors"] for r in res), "sent": sum(r["sent"] for r in res),
           "peak_lag": max(r["lag"] for r in timeline), "final_lag": timeline[-1]["lag"], "timeline": timeline, "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    print(json.dumps({k: v for k, v in out.items() if k != "timeline"}), flush=True)
    if a.json:
        open(a.json, "w").write(json.dumps(out, indent=1))


if __name__ == "__main__":
    mp.set_start_method("fork")
    main()
