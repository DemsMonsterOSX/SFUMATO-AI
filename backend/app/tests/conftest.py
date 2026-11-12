"""Test configuration: isolated SQLite database, demo CTI, deterministic AI, no embedded worker."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="sfumato-tests-"))
os.environ.update({
    "DATABASE_URL": f"sqlite:///{(_TMP / 'test.db').as_posix()}",
    "REDIS_URL": "",
    "CTI_MODE": "demo",
    "AI_PROVIDER": "deterministic",
    "EMBEDDED_WORKER": "false",
    "SEED_DEMO_INCIDENTS": "false",
    "API_KEYS": "test-key",
    "OLLAMA_URL": "",
    "ABUSECH_AUTH_KEY": "",
    "OTX_API_KEY": "",
    "OPENCTI_URL": "",
    "OPENCTI_TOKEN": "",
    "ANTHROPIC_API_KEY": "",
    "OPENAI_API_KEY": "",
    "RATE_LIMIT_PER_MINUTE": "10000",
})

from app.core.config import get_settings  # noqa: E402

get_settings.cache_clear()

from app.database.migrate import init_database  # noqa: E402
from app.ml.inference import model_service  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
HEADERS = {"X-API-Key": "test-key"}


@pytest.fixture(scope="session", autouse=True)
def _db():
    init_database()
    model_service.load()
    yield


def load_scenario(name: str, new_id: str | None = None) -> dict:
    path = next((REPO / "examples" / "incidents").glob(f"*_{name}.json"))
    data = json.loads(path.read_text(encoding="utf-8"))
    if new_id:
        data["incident_id"] = new_id
    return data


def run_pending_jobs() -> int:
    """Process every queued incident with a real worker (same code path as production)."""
    from app.workers.worker import Worker

    async def _run():
        w = Worker(concurrency=1)
        n = 0
        while True:
            job = w.claim()
            if not job:
                return n
            await w.process(*job)
            n += 1

    return asyncio.run(_run())


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
