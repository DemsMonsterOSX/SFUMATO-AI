"""Vulnerability feed (CISA KEV, NVD, EPSS) published to the bucket by bigdata/cve_ingest.py."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.core.security import require_api_key
from app.services import cve as cve_lib

router = APIRouter(prefix="/api/v1/cves", tags=["cves"], dependencies=[Depends(require_api_key)])


@router.get("/summary", summary="KEV, NVD and EPSS summary for the last ingestion window")
def summary():
    data, source = cve_lib.summary()
    return {"available": data is not None, "source": source, "summary": data}


@router.get("/search", summary="Search the CVEs held in the summary (KEV additions, top CVSS, top EPSS)")
def search(q: str = Query(..., min_length=2, max_length=100)):
    data, _ = cve_lib.summary()
    return {"available": data is not None, "items": cve_lib.search(data, q) if data else []}
