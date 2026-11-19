"""CVE bridge: turns the hourly CVE job's change list into events on the Kafka topic cve-events.

The Cloud Run job writes gs://BUCKET/cve/latest/events.jsonl (CVEs that are new, updated or newly in the KEV catalogue during its
last run) and manifest.json. Every minute the bridge checks the manifest; when a run it has not published yet appears, it
publishes each event (key = CVE id) and records the run's timestamp in gs://BUCKET/stream/state/cve-bridge.json, so a restart
does not republish the same run.
"""
from __future__ import annotations

import json
import time

import common as c


def main() -> None:
    c.require_bucket()
    prod = c.producer()
    c.log("cve-bridge started, bootstrap", c.BOOTSTRAP)
    while not c.stop:
        try:
            man = c.read_json("cve/latest/manifest.json")
            state = c.read_json("stream/state/cve-bridge.json") or {}
            if man and man["generated_at"] != state.get("last_generated_at"):
                blob = c.gcs().bucket(c.BUCKET).get_blob("cve/latest/events.jsonl")
                lines = [x for x in (blob.download_as_bytes().decode("utf-8").splitlines() if blob else []) if x.strip()]
                for line in lines:
                    ev = json.loads(line)
                    ev["run"] = man["generated_at"]
                    prod.produce(c.TOPIC_CVE, key=ev["id"], value=json.dumps(ev))
                prod.flush(30)
                c.write_state("cve-bridge", {"last_generated_at": man["generated_at"], "published": len(lines), "updated_at": time.time(), "host": c.HOST})
                c.log(f"published {len(lines)} CVE events for the run {man['generated_at']}")
        except Exception as e:  # noqa: BLE001
            c.log("bridge error:", type(e).__name__, str(e)[:120])
        for _ in range(60):
            if c.stop:
                break
            time.sleep(1)
    prod.flush(10)


if __name__ == "__main__":
    main()
