"""Live request metrics of the API (requests per second, latency percentiles, load)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.core import apimetrics
from app.core.security import require_api_key

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"], dependencies=[Depends(require_api_key)])


@router.get("/api", summary="Requests per second, latency percentiles and errors of this API process over the last minute")
def api_metrics(window: int = Query(60, ge=10, le=300)):
    return apimetrics.snapshot(window)
