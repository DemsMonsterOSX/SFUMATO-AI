"""Small key/value cache with TTL: Redis when REDIS_URL is set and reachable, in-process otherwise."""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.core.config import get_settings

log = logging.getLogger("sfumato.cache")


class Cache:
    def __init__(self) -> None:
        self._mem: dict[str, tuple[float, str]] = {}
        self._redis = None
        self._redis_checked = 0.0
        self.backend = "memory"

    def _client(self):
        url = get_settings().redis_url
        if not url:
            return None
        if self._redis is None and time.time() - self._redis_checked > 30:
            self._redis_checked = time.time()
            try:
                import redis

                client = redis.Redis.from_url(url, socket_timeout=1.5, socket_connect_timeout=1.5)
                client.ping()
                self._redis = client
                self.backend = "redis"
            except Exception as e:  # pragma: no cover - depends on infra
                log.warning("Redis unavailable (%s); using in-process cache", e)
                self.backend = "memory (redis unavailable)"
        return self._redis

    def get(self, key: str) -> Any | None:
        r = self._client()
        if r is not None:
            try:
                v = r.get(key)
                return json.loads(v) if v else None
            except Exception:
                self._redis = None
        item = self._mem.get(key)
        if not item:
            return None
        if item[0] < time.time():
            self._mem.pop(key, None)
            return None
        return json.loads(item[1])

    def set(self, key: str, value: Any, ttl: int) -> None:
        payload = json.dumps(value, default=str)
        r = self._client()
        if r is not None:
            try:
                r.setex(key, ttl, payload)
                return
            except Exception:
                self._redis = None
        if len(self._mem) > 5000:
            self._mem.clear()
        self._mem[key] = (time.time() + ttl, payload)

    def incr_window(self, key: str, window: int) -> int:
        """Fixed-window counter used for rate limiting."""
        r = self._client()
        if r is not None:
            try:
                pipe = r.pipeline()
                pipe.incr(key)
                pipe.expire(key, window)
                return int(pipe.execute()[0])
            except Exception:
                self._redis = None
        now = time.time()
        exp, val = self._mem.get(key, (now + window, "0"))
        if exp < now:
            exp, val = now + window, "0"
        n = int(val) + 1
        self._mem[key] = (exp, str(n))
        return n

    def healthy(self) -> dict:
        self._client()
        return {"backend": self.backend}


cache = Cache()
