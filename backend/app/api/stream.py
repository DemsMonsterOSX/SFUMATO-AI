"""Streaming (Kafka) status for the web app: live state of the pipeline and the measured results."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.security import require_api_key
from app.services import stream as stream_lib

router = APIRouter(prefix="/api/v1/stream", tags=["stream"], dependencies=[Depends(require_api_key)])


@router.get("/overview", summary="Live streaming state (if running) and the measured results of the Kafka pipeline")
def overview():
    return stream_lib.overview()
