"""Log analysis (Elasticsearch behind Logstash) for the Logs tab."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.security import require_api_key
from app.services import logs as logs_lib

router = APIRouter(prefix="/api/v1/logs", tags=["logs"], dependencies=[Depends(require_api_key)])


def _guard(fn, *a, **k):
    try:
        return fn(*a, **k)
    except ConnectionError as e:
        raise HTTPException(503, str(e))
    except Exception as e:
        raise HTTPException(502, f"log query failed ({type(e).__name__})")


@router.get("/status", summary="Is the log platform configured and reachable?")
def status():
    return logs_lib.status()


@router.get("/overview", summary="Counts by level and service, timeline, slowest and busiest routes over the last minutes")
def overview(minutes: int = Query(60, ge=5, le=1440), service: str | None = Query(None, max_length=60)):
    return _guard(logs_lib.overview, minutes, service)


@router.get("/search", summary="Search the logs (free text, service, level, time window)")
def search(q: str | None = Query(None, max_length=200), minutes: int = Query(60, ge=5, le=1440), service: str | None = Query(None, max_length=60),
           level: str | None = Query(None, max_length=10), size: int = Query(50, ge=1, le=200)):
    return _guard(logs_lib.search, q, minutes, service, level, size)
