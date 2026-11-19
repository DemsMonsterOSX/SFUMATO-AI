"""Log analysis: queries Elasticsearch (the log VM) for the web app's Logs tab.

Configuration: ELASTIC_URL (e.g. http://sfumato-elk.us-central1-a.c.PROJECT.internal:9200) and ELASTIC_PASSWORD, read from the
environment. Read-only queries on the sfumato-logs-* indices; free text goes to a simple_query_string, never to a script.
"""
from __future__ import annotations

import os
import re

import httpx

LEVELS = ("INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG")


def _cfg() -> tuple[str, str]:
    return os.environ.get("ELASTIC_URL", "").rstrip("/"), os.environ.get("ELASTIC_PASSWORD", "")


def _post(path: str, body: dict) -> dict:
    url, pw = _cfg()
    if not url or not pw:
        raise ConnectionError("the log platform is not configured on this deployment")
    with httpx.Client(timeout=10.0) as c:
        r = c.post(f"{url}/{path}", json=body, auth=("elastic", pw))
    if r.status_code >= 400:
        raise RuntimeError(f"Elasticsearch answered HTTP {r.status_code}")
    return r.json()


def _filters(minutes: int, service: str | None, level: str | None) -> list[dict]:
    f: list[dict] = [{"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}]
    if service and re.fullmatch(r"[A-Za-z0-9_.-]{1,60}", service):
        f.append({"term": {"service": service}})
    if level and level.upper() in LEVELS:
        f.append({"term": {"level": level.upper()}})
    return f


def status() -> dict:
    url, pw = _cfg()
    if not url or not pw:
        return {"configured": False, "reachable": False, "reason": "the log platform is not configured on this deployment"}
    try:
        with httpx.Client(timeout=4.0) as c:
            r = c.get(f"{url}/_cluster/health", auth=("elastic", pw))
        return {"configured": True, "reachable": r.status_code == 200, "cluster": r.json() if r.status_code == 200 else None,
                "reason": None if r.status_code == 200 else f"HTTP {r.status_code}"}
    except Exception as e:
        return {"configured": True, "reachable": False, "reason": "the log VM is not running or not reachable (" + type(e).__name__ + ")"}


def overview(minutes: int = 60, service: str | None = None) -> dict:
    body = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": _filters(minutes, service, None)}},
            "aggs": {
                "by_level": {"terms": {"field": "level", "size": 10}},
                "by_service": {"terms": {"field": "service", "size": 10}},
                "timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1m" if minutes <= 120 else "10m"},
                             "aggs": {"lvl": {"terms": {"field": "level", "size": 5}}}},
                "routes": {"terms": {"field": "route", "size": 8}, "aggs": {"avg_ms": {"avg": {"field": "ms"}}, "p95": {"percentiles": {"field": "ms", "percents": [95]}},
                                                                            "errors": {"filter": {"range": {"status": {"gte": 500}}}}}},
                "status_classes": {"range": {"field": "status", "ranges": [{"key": "2xx", "from": 200, "to": 300}, {"key": "3xx", "from": 300, "to": 400},
                                                                          {"key": "4xx", "from": 400, "to": 500}, {"key": "5xx", "from": 500, "to": 600}]}},
                "slowest": {"top_hits": {"size": 1, "sort": [{"ms": "desc"}], "_source": ["route", "ms", "@timestamp", "status"]}}}}
    d = _post("sfumato-logs-*/_search", body)
    a = d["aggregations"]
    return {"minutes": minutes, "total": d["hits"]["total"]["value"],
            "levels": {b["key"]: b["doc_count"] for b in a["by_level"]["buckets"]},
            "services": {b["key"]: b["doc_count"] for b in a["by_service"]["buckets"]},
            "timeline": [{"t": b["key_as_string"], "total": b["doc_count"], **{x["key"]: x["doc_count"] for x in b["lvl"]["buckets"]}} for b in a["timeline"]["buckets"]],
            "routes": [{"route": b["key"], "requests": b["doc_count"], "avg_ms": round(b["avg_ms"]["value"] or 0, 1), "p95_ms": round(next(iter(b["p95"]["values"].values())) or 0, 1),
                        "errors": b["errors"]["doc_count"]} for b in a["routes"]["buckets"]],
            "status_classes": {b["key"]: b["doc_count"] for b in a["status_classes"]["buckets"]},
            "slowest": [h["_source"] for h in a["slowest"]["hits"]["hits"]]}


def search(q: str | None, minutes: int, service: str | None, level: str | None, size: int = 50) -> dict:
    must: list[dict] = [{"simple_query_string": {"query": q[:200], "fields": ["message", "route", "service"], "default_operator": "and"}}] if q and q.strip() else []
    body = {"size": size, "sort": [{"@timestamp": "desc"}], "track_total_hits": True,
            "query": {"bool": {"filter": _filters(minutes, service, level), "must": must}},
            "_source": ["@timestamp", "service", "level", "message", "route", "method", "status", "ms", "host", "logger"]}
    d = _post("sfumato-logs-*/_search", body)
    return {"total": d["hits"]["total"]["value"], "items": [h["_source"] for h in d["hits"]["hits"]]}
