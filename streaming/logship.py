"""Ships application log events to Logstash over HTTP (fire and forget).

Enabled only when LOGSTASH_URL and LOGSTASH_TOKEN are set. Events are queued in memory and sent in batches by one background thread;
when the queue is full or Logstash is unreachable events are dropped silently: logging must never slow down or break a request.
Event fields: service, level, message, plus free keys (route, method, status, ms, host). "ts" is the UNIX time of the event.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import socket
import threading
import time
import urllib.request
import base64

_q: queue.Queue = queue.Queue(maxsize=5000)
_started = False
_lock = threading.Lock()
HOST = socket.gethostname().split(".")[0]


def enabled() -> bool:
    return bool(os.environ.get("LOGSTASH_URL") and os.environ.get("LOGSTASH_TOKEN"))


def _worker() -> None:
    url = os.environ["LOGSTASH_URL"]
    auth = "Basic " + base64.b64encode(f"logship:{os.environ['LOGSTASH_TOKEN']}".encode()).decode()
    while True:
        batch = [_q.get()]
        t0 = time.time()
        while len(batch) < 200 and time.time() - t0 < 1.0:
            try:
                batch.append(_q.get(timeout=0.2))
            except queue.Empty:
                break
        try:
            req = urllib.request.Request(url, data=json.dumps(batch).encode("utf-8"), headers={"Content-Type": "application/json", "Authorization": auth})
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:
            pass   # unreachable or refused: drop the batch


def emit(service: str, level: str, message: str, **fields) -> None:
    global _started
    if not enabled():
        return
    with _lock:
        if not _started:
            threading.Thread(target=_worker, name="logship", daemon=True).start()
            _started = True
    try:
        _q.put_nowait({"ts": time.time(), "service": service, "level": level.upper(), "message": message[:2000], "host": HOST, **fields})
    except queue.Full:
        pass


class LogstashHandler(logging.Handler):
    """Python logging handler: WARNING and above of the application loggers go to Logstash."""

    def __init__(self, service: str):
        super().__init__(level=logging.WARNING)
        self.service = service

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D102
        try:
            emit(self.service, record.levelname, self.format(record), logger=record.name)
        except Exception:
            pass
