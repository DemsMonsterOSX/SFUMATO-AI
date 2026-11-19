"""Streaming (Kafka) status for the web app: live state of the pipeline and the measured results."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.security import audit, require_api_key
from app.services import stream as stream_lib

router = APIRouter(prefix="/api/v1/stream", tags=["stream"], dependencies=[Depends(require_api_key)])


@router.get("/overview", summary="Live streaming state (if running) and the measured results of the Kafka pipeline")
def overview():
    return stream_lib.overview()


class StressRequest(BaseModel):
    max_rate: int = Field(7200, ge=300, le=7200, description="highest target rate tested, flows per second")
    step_seconds: int = Field(30, ge=15, le=45)


@router.get("/stress", summary="Progress and results of the current or last stress test (and whether the controller is reachable)")
def stress_status():
    return stream_lib.stress_status()


@router.post("/stress", status_code=202, summary="Start a stress test: ramp the flow rate to find the maximum sustainable throughput")
def stress_start(req: StressRequest, request: Request):
    code, body = stream_lib.stress_start(req.max_rate, req.step_seconds)
    if code >= 400:
        raise HTTPException(code, body.get("detail", "stress test refused"))
    try:
        audit(request, "stream.stress.start", f"max_rate={req.max_rate} step={req.step_seconds}s")
    except Exception:
        pass
    return body
