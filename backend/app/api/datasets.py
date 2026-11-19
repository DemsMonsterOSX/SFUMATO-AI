"""Read-only dataset browser over the project's bucket (allow-listed prefixes only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.security import require_api_key
from app.services import datasets as ds

router = APIRouter(prefix="/api/v1/datasets", tags=["datasets"], dependencies=[Depends(require_api_key)])


@router.get("", summary="Exposed dataset locations, or the files under one of them (prefix=...)")
def browse(prefix: str | None = Query(None, max_length=200)):
    if not prefix:
        return {"roots": ds.roots()}
    try:
        return {"roots": ds.roots(), **ds.listing(prefix)}
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/preview", summary="First rows of a CSV or the start of a text file (reads at most 256 KB)")
def preview(path: str = Query(..., max_length=300), rows: int = Query(20, ge=1, le=100)):
    try:
        return ds.preview(path, rows)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
