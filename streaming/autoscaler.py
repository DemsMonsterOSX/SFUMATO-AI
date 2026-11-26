"""Lag-driven autoscaler for the scorer tier (runs inside the controller on kafka-1).

Scorers are members of one Kafka consumer group sharing the 6 partitions of network-flows. When the backlog (lag) stays high the
autoscaler starts one more worker VM (sfumato-scorer-1, then -2); when the backlog stays near zero for a while it stops one. The worker
VMs only run the scorer; the group rebalances by itself when a member joins or leaves. Between 3 (the Kafka VMs) and 5 scorers; the topic
has 6 partitions, so a sixth member would stay idle.

The decision is a pure function (decide) so it can be tested without Kafka or Google Cloud. The VM calls go through the Compute API
with the VM's service account, which is allowed to start and stop the worker VMs only (IAM condition on the instance name).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

OUT_LAG = int(os.environ.get("AUTOSCALE_OUT_LAG", "3000"))       # messages behind before adding a scorer
IN_LAG = int(os.environ.get("AUTOSCALE_IN_LAG", "300"))          # messages behind below which a scorer can be removed
OUT_HOLD_S = int(os.environ.get("AUTOSCALE_OUT_HOLD", "20"))     # the backlog must stay high this long
IN_HOLD_S = int(os.environ.get("AUTOSCALE_IN_HOLD", "240"))      # the backlog must stay low this long
COOLDOWN_S = int(os.environ.get("AUTOSCALE_COOLDOWN", "90"))     # minimum time between two actions
WORKERS = [w for w in os.environ.get("AUTOSCALE_WORKERS", "sfumato-scorer-1,sfumato-scorer-2").split(",") if w]


def decide(s: dict, now: float, lag: int, running: int, total: int, *, out_lag: int = OUT_LAG, in_lag: int = IN_LAG,
           out_hold: int = OUT_HOLD_S, in_hold: int = IN_HOLD_S, cooldown: int = COOLDOWN_S) -> str | None:
    """Returns "out", "in" or None. s is the memory between calls: above_since, below_since, last_action (times, or None)."""
    cooled = now - (s.get("last_action") or 0) >= cooldown
    if lag >= out_lag:
        s["below_since"] = None
        s["above_since"] = s.get("above_since") or now
        if running < total and cooled and now - s["above_since"] >= out_hold:
            s["last_action"], s["above_since"] = now, None
            return "out"
    elif lag <= in_lag:
        s["above_since"] = None
        s["below_since"] = s.get("below_since") or now
        if running > 0 and cooled and now - s["below_since"] >= in_hold:
            s["last_action"], s["below_since"] = now, None
            return "in"
    else:
        s["above_since"] = s["below_since"] = None
    return None


class Gce:
    """Start, stop and read worker VMs with the Compute API (token from the metadata server)."""
    MD = "http://metadata.google.internal/computeMetadata/v1/"

    def __init__(self):
        self.project = self._md("project/project-id")
        self.zone = self._md("instance/zone").rsplit("/", 1)[-1]

    def _md(self, path: str) -> str:
        r = urllib.request.Request(self.MD + path, headers={"Metadata-Flavor": "Google"})
        return urllib.request.urlopen(r, timeout=5).read().decode()

    def _call(self, method: str, name: str, action: str = "") -> dict:
        tok = json.loads(self._md("instance/service-accounts/default/token"))["access_token"]
        url = f"https://compute.googleapis.com/compute/v1/projects/{self.project}/zones/{self.zone}/instances/{name}{action}"
        r = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None, headers={"Authorization": f"Bearer {tok}"})
        with urllib.request.urlopen(r, timeout=20) as x:
            return json.loads(x.read().decode() or "{}")

    def status(self, name: str) -> str:
        try:
            return self._call("GET", name).get("status", "UNKNOWN")
        except urllib.error.HTTPError as e:
            return f"ERROR {e.code}"

    def start(self, name: str) -> None:
        self._call("POST", name, "/start")

    def stop(self, name: str) -> None:
        self._call("POST", name, "/stop")


def loop(lag_fn, log, write_state, interval: int = 10) -> None:
    """lag_fn() -> current backlog of the scorer group. Runs forever; every error is logged and the loop continues."""
    gce = Gce()
    mem: dict = {}
    events: list = []
    c_start = time.time()
    while True:
        try:
            now = time.time()
            lag = int(lag_fn())
            status = {w: gce.status(w) for w in WORKERS}
            on = [w for w, st in status.items() if st in ("RUNNING", "STAGING", "PROVISIONING")]
            action = decide(mem, now, lag, len(on), len(WORKERS))
            if action == "out":
                target = next(w for w in WORKERS if w not in on)
                gce.start(target)
                events.append({"at": now, "action": "scale_out", "vm": target, "lag": lag})
                log(f"autoscale: lag {lag} -> start {target}")
            elif action == "in":
                target = on[-1]
                gce.stop(target)
                events.append({"at": now, "action": "scale_in", "vm": target, "lag": lag})
                log(f"autoscale: lag {lag} -> stop {target}")
            write_state("autoscale", {"enabled": True, "lag": lag, "workers": status, "min_scorers": 3, "max_scorers": 3 + len(WORKERS),
                                      "policy": {"out_lag": OUT_LAG, "in_lag": IN_LAG, "out_hold_s": OUT_HOLD_S, "in_hold_s": IN_HOLD_S, "cooldown_s": COOLDOWN_S},
                                      "events": events[-30:], "updated_at": now, "since": c_start})
        except Exception as e:  # noqa: BLE001 - the scaler must never stop because of one failed call
            log(f"autoscale error: {type(e).__name__}: {str(e)[:160]}")
        time.sleep(interval)
