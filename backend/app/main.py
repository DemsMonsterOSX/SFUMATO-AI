"""Sfumato Autonomous SOC — FastAPI application."""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from app.api import incidents, intel, system
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.core.security import RequestGuardMiddleware
from app.database.migrate import init_database
from app.database.session import session_scope
from app.knowledge import knowledge_base
from app.ml.guide_inference import guide_service
from app.ml.inference import model_service
from app.models import Incident
from app.schemas.incident import IncidentIn
from app.services import ingestion
from app.workers.worker import Worker

log = logging.getLogger("sfumato")


def seed_demo_incidents() -> int:
    """On an empty database, submit the three principal demo incidents through the normal pipeline."""
    settings = get_settings()
    with session_scope() as s:
        if s.scalar(select(func.count()).select_from(Incident)):
            return 0
    base = Path(settings.examples_dir) / "incidents"
    idx = base / "index.json"
    if not idx.exists():
        return 0
    n = 0
    for sc in json.loads(idx.read_text(encoding="utf-8")):
        if not sc.get("seed"):
            continue
        payload = IncidentIn.model_validate(json.loads((base / sc["file"]).read_text(encoding="utf-8")))
        ingestion.submit(payload, cti_mode="demo", via="seed")
        n += 1
    return n


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    settings = get_settings()
    await asyncio.to_thread(init_database)
    await asyncio.to_thread(model_service.load)
    guide_service.start_background_sync()  # reference model from the bucket, without blocking start-up
    knowledge_base.start_background_sync()  # downloads/loads the RAG knowledge base without blocking start-up
    worker_task = None
    if settings.embedded_worker:
        worker = Worker()
        system.set_worker(worker)
        worker_task = asyncio.create_task(worker.run_forever())
    if settings.seed_demo_incidents:
        seeded = await asyncio.to_thread(seed_demo_incidents)
        if seeded:
            log.info("Seeded %d demonstration incidents (CTI demo fixtures)", seeded)
    log.info("Sfumato Autonomous SOC ready — CTI mode %s, deployment %s", settings.cti_mode, settings.deployment_mode)
    yield
    if worker_task:
        worker_task.cancel()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Sfumato Autonomous SOC API",
        version=settings.app_version,
        description="Autonomous incident investigation: SOAR orchestration, CTI enrichment, ML, AI investigator "
                    "and explainable verdicts. All endpoints except /api/v1/health require the `X-API-Key` header. "
                    "Response actions are recommendations only — the platform never executes remediation.",
        lifespan=lifespan,
        contact={"name": "Florian Payet, Damien Leclercq, Adrien Scazzola"},
    )
    app.add_middleware(RequestGuardMiddleware)
    app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
                       allow_methods=["GET", "POST", "PUT"], allow_headers=["X-API-Key", "Content-Type"])

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        errors = [{"loc": ".".join(str(p) for p in e["loc"]), "msg": e["msg"], "type": e["type"]}
                  for e in exc.errors()]
        return JSONResponse({"detail": "Incident validation failed" if request.url.path.endswith("/incidents")
                             else "Validation failed", "errors": errors}, status_code=422)

    @app.get("/", include_in_schema=False)
    def root():
        return {"name": settings.app_name, "docs": "/docs", "health": "/api/v1/health"}

    app.include_router(system.public)
    app.include_router(system.router)
    app.include_router(incidents.router)
    app.include_router(intel.router)
    return app


app = create_app()
