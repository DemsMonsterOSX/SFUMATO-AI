"""Flink results reader: consumes flow-aggregates and rule-alerts and publishes them for the web app.

Runs on the sfumato-flink VM next to Flink. Writes gs://BUCKET/stream/state/flink.json: the last windows, the latest rule alerts and
counters, plus how well the rule alerts match the replay labels (a measurement, not an input of the rules).
"""
from __future__ import annotations

import json
import time
from collections import Counter, deque

import common as c


def main() -> None:
    c.require_bucket()
    cons = c.consumer("flink-state", {"auto.offset.reset": "latest"})
    cons.subscribe(["flow-aggregates", "rule-alerts"])
    windows, alerts = deque(maxlen=90), deque(maxlen=60)
    by_rule: Counter = Counter()
    att_in_alert = flows_in_alert = 0
    total_windows = 0
    last = time.time()
    c.log("flink-state started")
    while not c.stop:
        got = 0
        for m in cons.consume(num_messages=200, timeout=1.0):
            if m.error():
                continue
            got += 1
            try:
                d = json.loads(m.value())
            except Exception:  # noqa: BLE001
                continue
            if m.topic() == "flow-aggregates":
                windows.append(d)
                total_windows += 1
            else:
                alerts.appendleft(d)
                by_rule[d.get("rule", "?")] += 1
                flows_in_alert += d.get("flows", 0)
                att_in_alert += d.get("attack_flows", 0)
        if got:
            cons.commit(asynchronous=False)
        if time.time() - last > 8:
            c.write_state("flink", {"host": c.HOST, "windows": list(windows), "alerts": list(alerts)[:30], "windows_seen": total_windows,
                                    "alerts_by_rule": dict(by_rule), "alert_flows": flows_in_alert,
                                    "alert_attack_share": round(att_in_alert / flows_in_alert, 4) if flows_in_alert else None, "updated_at": time.time()})
            last = time.time()
    cons.close()


if __name__ == "__main__":
    main()
