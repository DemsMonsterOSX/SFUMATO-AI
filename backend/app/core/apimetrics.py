"""In-memory request metrics of the API (last few thousand requests): requests per second, latency percentiles, errors per route.

Per process and lost on restart, by design: it is a live view for the API console and for load tests, not a monitoring system.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque

_lock = threading.Lock()
_events: deque = deque(maxlen=20000)   # (timestamp, route, status, milliseconds)
_started = time.time()


def record(route: str, status: int, ms: float) -> None:
    with _lock:
        _events.append((time.time(), route, status, ms))


def _pct(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * len(xs)))], 1)


def snapshot(window_s: int = 60) -> dict:
    now = time.time()
    with _lock:
        ev = [e for e in _events if now - e[0] <= window_s]
    per: dict[str, list] = {}
    for _, route, status, ms in ev:
        per.setdefault(route, []).append((status, ms))
    routes = sorted(({"route": r, "requests": len(v), "errors": sum(1 for s, _ in v if s >= 500), "client_errors": sum(1 for s, _ in v if 400 <= s < 500),
                      "p50_ms": _pct([m for _, m in v], 0.5), "p95_ms": _pct([m for _, m in v], 0.95)} for r, v in per.items()), key=lambda x: -x["requests"])
    last10 = [e for e in ev if now - e[0] <= 10]
    mem = None
    try:
        info = dict(l.split(":", 1) for l in open("/proc/meminfo").read().splitlines())
        mem = {"total_mb": int(info["MemTotal"].split()[0]) // 1024, "available_mb": int(info["MemAvailable"].split()[0]) // 1024}
    except Exception:
        pass
    return {"window_s": window_s, "requests": len(ev), "rps_window": round(len(ev) / window_s, 2), "rps_last_10s": round(len(last10) / 10, 2),
            "p50_ms": _pct([e[3] for e in ev], 0.5), "p95_ms": _pct([e[3] for e in ev], 0.95), "p99_ms": _pct([e[3] for e in ev], 0.99),
            "errors_5xx": sum(1 for e in ev if e[2] >= 500), "routes": routes[:15], "uptime_s": round(now - _started),
            "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None, "memory": mem, "cpu_count": os.cpu_count()}
