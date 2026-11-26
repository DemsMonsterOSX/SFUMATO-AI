"""Stress-test controller: a tiny HTTP service (internal network only) that finds the maximum sustainable throughput of the pipeline.

Runs on kafka-1 (role "controller"). The dashboard backend calls it over the project's internal network with a shared token:
  POST /stress   {"max_rate": 7200, "step_seconds": 30}  -> 202, starts a ramp (one test at a time)
  GET  /stress   -> progress and results of the current or last test
  GET  /health

The ramp: for each target rate (300, 600, 1200, 2400, 4800, 7200 flows/s, up to max_rate, minus what the regular replay producer already sends) one or more stress producers
(stress_producer.py) run for step_seconds while the Kafka offsets are read: produced per second (change of the end offsets),
consumed per second (change of the committed offsets of the scorer group) and the backlog (lag). A step PASSES when the scorers
consume at least 95 % of what was produced and the backlog at the end stays under three seconds of traffic. The ramp stops at
the first failing step; the maximum sustainable rate is the last passing target. After the last step the backlog drain time is
recorded. A test lasts at most about five minutes. Scorers must be running (scripts/gcp_stream.ps1 run).
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import common as c

TOKEN = os.environ.get("CONTROL_TOKEN", "")
PORT = int(os.environ.get("CONTROL_PORT", "8088"))
STEPS = [300, 600, 1200, 2400, 4800, 7200]
state: dict = {"status": "idle"}
lock = threading.Lock()


def offsets(group: str):
    """(end offsets sum, committed offsets sum, lag) for the topic network-flows and the given group, without joining it."""
    from confluent_kafka import TopicPartition
    cons = c.consumer(group)
    try:
        md = cons.list_topics(c.TOPIC_FLOWS, timeout=10).topics[c.TOPIC_FLOWS]
        tps = [TopicPartition(c.TOPIC_FLOWS, p) for p in md.partitions]
        end = committed = 0
        for tp, com in zip(tps, cons.committed(tps, timeout=10)):
            lo, hi = cons.get_watermark_offsets(tp, timeout=10, cached=False)
            end += hi
            committed += com.offset if com.offset >= 0 else lo
        return end, committed, end - committed
    finally:
        cons.close()


SCORER_HOSTS = ("sfumato-kafka-1", "sfumato-kafka-2", "sfumato-kafka-3", "sfumato-scorer-1", "sfumato-scorer-2")   # the last two are the autoscaled workers


def scorer_p95() -> float | None:
    vals = []
    for h in SCORER_HOSTS:
        d = c.read_json(f"stream/state/scorer-{h}.json")
        if d and time.time() - d.get("updated_at", 0) < 30 and d["latency_ms"]["p95"] is not None:
            vals.append(d["latency_ms"]["p95"])
    return max(vals) if vals else None


def active_scorers() -> int:
    n = 0
    for h in SCORER_HOSTS:
        d = c.read_json(f"stream/state/scorer-{h}.json")
        if d and time.time() - d.get("updated_at", 0) < 30:
            n += 1
    return n


def background_rate() -> float:
    """Flows per second already sent by the regular replay producer (counted in the offsets, so it must be subtracted)."""
    total = 0.0
    for h in ("sfumato-kafka-1", "sfumato-kafka-2", "sfumato-kafka-3"):
        d = c.read_json(f"stream/state/producer-{h}.json")
        if d and time.time() - d.get("updated_at", 0) < 30:
            total += d.get("target_rate", 0)
    return total


def run_ramp(max_rate: int, step_s: int) -> None:
    scenario = c.SCENARIO
    group = f"scorers-{scenario}"
    steps_out: list[dict] = []
    started = time.time()
    with lock:
        state.clear()
        state.update(status="running", started_at=started, scenario=scenario, steps=steps_out, max_sustainable=None, max_target_passed=None,
                     active_scorers=active_scorers(), note="Producers run on kafka-1; the scorers of the group share the load.")
    try:
        # warm-up: wait for the three scorers and for an empty backlog, so the first step is not distorted
        t_w = time.time()
        while time.time() - t_w < 60 and (active_scorers() < 3 or offsets(group)[2] > 500):
            time.sleep(2)
        bg = background_rate()
        with lock:
            state.update(active_scorers=active_scorers(), background_rate=bg, warmup_seconds=round(time.time() - t_w))
        if state["active_scorers"] == 0:
            raise RuntimeError("no scorer is running: start the pipeline with scripts/gcp_stream.ps1 run")
        best_rate, best_target, ceiling = None, None, "maximum tested rate reached"
        for target in [s for s in STEPS if s <= max_rate]:
            stress_rate = max(50.0, target - bg)   # the regular producer already contributes bg flows per second
            procs_n = max(1, math.ceil(stress_rate / 2500))
            e0, k0, _ = offsets(group)
            t0 = time.time()
            with lock:
                state["current_target"] = target
            procs = [subprocess.Popen([sys.executable, "-u", os.path.join(os.path.dirname(__file__), "stress_producer.py"), "--rate", str(stress_rate / procs_n),
                                       "--seconds", str(step_s), "--scenario", scenario, "--tag", f"s{target}p{i}"], stdout=subprocess.PIPE, text=True,
                                      env=os.environ.copy()) for i in range(procs_n)]
            outs = [json.loads((p.communicate(timeout=step_s + 90)[0].strip().splitlines() or ["{}"])[-1] or "{}") for p in procs]
            dt = time.time() - t0
            e1, k1, lag = offsets(group)
            errors = sum(o.get("errors", 0) for o in outs)
            produced_rate, consumed_rate = (e1 - e0) / dt, (k1 - k0) / dt
            consumers_ok = consumed_rate >= 0.95 * max(produced_rate, 1) and lag <= 3 * max(produced_rate, 1)
            producer_limited = produced_rate < 0.9 * target
            ok = errors == 0 and consumers_ok
            reason = None if (ok and not producer_limited) else (
                "producer could not reach the target rate (consumers kept up: the real limit is higher)" if ok else
                "consumers fell behind (backlog growing)" if errors == 0 else "delivery errors")
            row = {"target": target, "stress_producers": procs_n, "background_rate": bg, "produced_per_s": round(produced_rate), "consumed_per_s": round(consumed_rate),
                   "lag_end": lag, "p95_latency_ms": scorer_p95(), "errors": errors, "passed": ok, "consumers_ok": consumers_ok,
                   "producer_limited": producer_limited, "reason": reason}
            with lock:
                steps_out.append(row)
            if ok:
                best_rate, best_target = round(consumed_rate), target
                with lock:
                    state.update(max_sustainable=best_rate, max_target_passed=best_target)
            if not ok:
                ceiling = "consumers (the scorers fell behind)"
                break
            if producer_limited:
                ceiling = "producer on one VM (lower bound: the scorers kept up)"
                break
        t1 = time.time()
        lag = offsets(group)[2]
        while lag > 50 and time.time() - t1 < 90:
            time.sleep(2)
            lag = offsets(group)[2]
        with lock:
            state.update(status="done", finished_at=time.time(), drain_seconds=round(time.time() - t1, 1), lag_after_drain=lag, duration_s=round(time.time() - started),
                         current_target=None, ceiling=ceiling,
                         verdict=f"highest rate consumed without falling behind: {best_rate or 0} flows/s; the limit seen is the {ceiling}")
    except Exception as e:  # noqa: BLE001
        with lock:
            state.update(status="error", error=f"{type(e).__name__}: {str(e)[:200]}", finished_at=time.time())
    finally:
        with lock:
            snap = dict(state)
        c.write_state("stress-last", snap)


class H(BaseHTTPRequestHandler):
    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _auth(self) -> bool:
        if not TOKEN or self.headers.get("X-Token") != TOKEN:
            self._send({"detail": "unauthorised"}, 401)
            return False
        return True

    def do_GET(self):
        if self.path == "/health":
            return self._send({"ok": True, "host": c.HOST, "scenario": c.SCENARIO})
        if self.path == "/stress" and self._auth():
            with lock:
                return self._send(dict(state))
        self._send({"detail": "not found"}, 404)

    def do_POST(self):
        if self.path != "/stress" or not self._auth():
            return
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        with lock:
            if state.get("status") == "running":
                return self._send({"detail": "a stress test is already running"}, 409)
        max_rate = max(300, min(int(body.get("max_rate", 7200)), 7200))
        step = max(15, min(int(body.get("step_seconds", 30)), 45))
        threading.Thread(target=run_ramp, args=(max_rate, step), daemon=True).start()
        self._send({"started": True, "max_rate": max_rate, "step_seconds": step}, 202)

    def log_message(self, *a):
        pass


def main() -> None:
    c.require_bucket()
    if not TOKEN:
        c.log("CONTROL_TOKEN is not set: refusing to start")
        sys.exit(1)
    last = c.read_json("stream/state/stress-last.json")
    if last:
        state.clear()
        state.update(last)
    if os.environ.get("AUTOSCALE", "0") == "1":
        import autoscaler
        group = f"scorers-{c.SCENARIO}"
        threading.Thread(target=autoscaler.loop, args=(lambda: offsets(group)[2], c.log, c.write_state), daemon=True, name="autoscaler").start()
        c.log(f"autoscaler on: workers {autoscaler.WORKERS}, out at lag {autoscaler.OUT_LAG}, in at lag {autoscaler.IN_LAG}")
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    c.log(f"stress controller on :{PORT}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
