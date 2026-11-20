"""Tiny in-process TTL cache for read-only, argument-keyed GET handlers (the API runs as one process on a 0.25-vCPU VM).

Why: the load test (ml/scale/before_*.json) showed the heavy read endpoints collapsing above about 8 parallel connections because each
request re-read JSON files or re-ran the BM25 search. The data behind them changes at most every few hours, so a short TTL is safe.
Not shared between processes and lost at restart; entries are bounded so a client cannot grow memory with random queries.
"""
from __future__ import annotations

import functools
import threading
import time

_MAX_ENTRIES = 256


def ttl_cache(seconds: float):
    def deco(fn):
        store: dict = {}
        lock = threading.Lock()

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            key = (args, tuple(sorted(kwargs.items())))
            now = time.monotonic()
            with lock:
                hit = store.get(key)
                if hit and now - hit[0] < seconds:
                    return hit[1]
            value = fn(*args, **kwargs)
            with lock:
                if len(store) >= _MAX_ENTRIES:
                    store.clear()
                store[key] = (now, value)
            return value

        wrapper.cache_clear = lambda: store.clear()  # type: ignore[attr-defined]
        return wrapper
    return deco
