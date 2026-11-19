"""Vulnerability feed (CISA KEV, NVD, EPSS) published to the bucket by bigdata/cve_ingest.py."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

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


@router.get("/lookup/{cve_id}", summary="Fetch one CVE live (NIST NVD, CISA KEV, FIRST EPSS)")
def lookup(cve_id: str):
    try:
        data = cve_lib.lookup(cve_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except cve_lib.RateLimited as e:
        raise HTTPException(429, str(e))
    except Exception as e:
        raise HTTPException(502, f"upstream lookup failed ({type(e).__name__})")
    if data is None:
        raise HTTPException(404, "this CVE is not in the NVD")
    return data
