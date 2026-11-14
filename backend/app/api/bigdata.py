"""Big Data lab: pipeline description and the figures produced by the Spark job (ml/bigdata/results.json).

Nothing is invented here: when the Spark job has not been run and published, `results` is null and the page says so.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends

from app.core.config import get_settings
from app.core.security import require_api_key

router = APIRouter(prefix="/api/v1/bigdata", tags=["bigdata"], dependencies=[Depends(require_api_key)])

STAGES = [
    {"id": "acquire", "phase": "Phase 1", "title": "Acquisition", "tech": "Cloud Storage",
     "what": "10 CSV files of CSE-CIC-IDS2018 (6.9 GB) streamed from a public bucket into the project's own bucket."},
    {"id": "batch", "phase": "Phase 2", "title": "Batch processing", "tech": "Spark on Dataproc Serverless",
     "what": "Union of two CSV layouts, removal of embedded headers, Infinity/NaN and negative durations, Parquet partitioned by day."},
    {"id": "sql", "phase": "Phase 2", "title": "SQL analytics", "tech": "BigQuery",
     "what": "OLAP queries over the clean Parquet: class balance, attacks per day and hour, behavioural fingerprints, targeted ports."},
    {"id": "ml", "phase": "Phase 4", "title": "Machine learning", "tech": "Spark MLlib",
     "what": "Random Forest on a random split and a time hold-out; multiclass; leave-one-family-out vs a KMeans anomaly detector."},
    {"id": "viz", "phase": "Phase 5", "title": "Visualisation", "tech": "This page + report.py",
     "what": "Charts built only from results.json."},
]


def _results_path(name: str = "results.json") -> Path:
    return Path(get_settings().repo_dir) / "ml" / "bigdata" / name


def _load(name: str):
    p = _results_path(name)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


@router.get("/overview", summary="Pipeline stages, dataset facts and the Spark results when they have been published")
def overview():
    results = _load("results.json")
    return {
        "dataset": {"name": "CSE-CIC-IDS2018 (processed traffic for ML)", "size_gb": 6.89, "files": 10,
                    "source": "AWS Open Data, Canadian Institute for Cybersecurity + CSE", "domain": "network intrusion detection"},
        "stages": STAGES,
        "results": results,
        "advanced": _load("advanced.json"),
        "results_published": results is not None,
    }
