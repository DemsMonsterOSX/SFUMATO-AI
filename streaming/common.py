"""Shared helpers for the Sfumato streaming applications (Kafka + Cloud Storage).

Configuration comes from environment variables written by the VM sync script from the instance metadata:
BOOTSTRAP (comma-separated brokers), BUCKET, SCENARIO (known|unseen), RATE (flows per second), THRESHOLD.
"""
from __future__ import annotations

import json
import os
import sys as _sys
import signal
import socket
import sys
import time
from pathlib import Path

HOST = socket.gethostname().split(".")[0]
BOOTSTRAP = os.environ.get("BOOTSTRAP", "localhost:9092")
BUCKET = os.environ.get("BUCKET", "")
SCENARIO = os.environ.get("SCENARIO", "known")
RATE = float(os.environ.get("RATE", "300"))
THRESHOLD = float(os.environ.get("THRESHOLD", "0.5"))
TOPIC_FLOWS, TOPIC_ALERTS, TOPIC_DLQ, TOPIC_CVE = "network-flows", "alerts", "network-flows-dlq", "cve-events"
CACHE = Path(os.environ.get("CACHE_DIR", "/tmp/sfumato-stream-cache"))

_client = None
stop = False


def _sig(*_):
    global stop
    stop = True


signal.signal(signal.SIGTERM, _sig)
signal.signal(signal.SIGINT, _sig)


SERVICE = Path(_sys.argv[0]).stem if _sys.argv and _sys.argv[0] else "streaming"


def log(*a):
    print(time.strftime("%H:%M:%S"), HOST, *a, flush=True)
    try:   # also ship to Logstash when LOGSTASH_URL / LOGSTASH_TOKEN are set (log VM running); never raises
        import logship
        logship.emit(SERVICE, "INFO", " ".join(str(x) for x in a))
    except Exception:  # noqa: BLE001
        pass


def gcs():
    global _client
    if _client is None:
        from google.cloud import storage
        _client = storage.Client()
    return _client


def download(name: str, dest: Path | None = None) -> Path:
    """Download gs://BUCKET/name into the local cache (re-downloaded only if the size differs)."""
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = dest or CACHE / name.replace("/", "_")
    blob = gcs().bucket(BUCKET).get_blob(name)
    if blob is None:
        raise FileNotFoundError(f"gs://{BUCKET}/{name}")
    if not dest.exists() or dest.stat().st_size != blob.size:
        blob.download_to_filename(str(dest))
    return dest


def read_json(name: str):
    blob = gcs().bucket(BUCKET).get_blob(name)
    return json.loads(blob.download_as_bytes()) if blob else None


def write_state(name: str, obj: dict) -> None:
    """Small JSON documents read by the web app (gs://BUCKET/stream/state/<name>.json). Best effort: never stops a stream."""
    try:
        gcs().bucket(BUCKET).blob(f"stream/state/{name}.json").upload_from_string(json.dumps(obj), content_type="application/json")
    except Exception as e:  # noqa: BLE001
        log("state write failed:", type(e).__name__)


def producer(extra: dict | None = None):
    from confluent_kafka import Producer
    cfg = {"bootstrap.servers": BOOTSTRAP, "acks": "all", "enable.idempotence": True, "compression.type": "lz4", "linger.ms": 20,
           "client.id": f"{HOST}-producer"}
    return Producer({**cfg, **(extra or {})})


def consumer(group: str, extra: dict | None = None):
    from confluent_kafka import Consumer
    cfg = {"bootstrap.servers": BOOTSTRAP, "group.id": group, "enable.auto.commit": False, "auto.offset.reset": "latest",
           "client.id": f"{HOST}-{group}", "session.timeout.ms": 15000}
    return Consumer({**cfg, **(extra or {})})


def percentile(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    s = sorted(xs)
    return round(s[min(len(s) - 1, int(q * len(s)))], 1)


def require_bucket() -> None:
    if not BUCKET:
        log("BUCKET is not set")
        sys.exit(1)
