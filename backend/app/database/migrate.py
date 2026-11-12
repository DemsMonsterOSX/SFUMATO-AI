"""Automatic database migrations (Alembic) executed at start-up, with connection retries."""
from __future__ import annotations

import logging
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from app.core.config import get_settings
from app.database.session import get_engine

log = logging.getLogger("sfumato.db")
BACKEND_DIR = Path(__file__).resolve().parents[2]


def wait_for_database(retries: int = 40, delay: float = 1.5) -> None:
    last = None
    for attempt in range(1, retries + 1):
        try:
            with get_engine().connect() as c:
                c.execute(text("SELECT 1"))
            return
        except Exception as e:  # pragma: no cover - depends on infra timing
            last = e
            log.warning("Database not ready (attempt %d/%d): %s", attempt, retries, e.__class__.__name__)
            time.sleep(delay)
    raise RuntimeError(f"Database unreachable at {get_settings().database_url.split('@')[-1]}: {last}")


def init_database() -> None:
    wait_for_database()
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    engine = get_engine()
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            # API and worker containers start together: serialise migrations with an advisory lock.
            conn.execute(text("SELECT pg_advisory_lock(424242)"))
        cfg.attributes["connection"] = conn
        try:
            command.upgrade(cfg, "head")
        finally:
            if engine.dialect.name == "postgresql":
                conn.execute(text("SELECT pg_advisory_unlock(424242)"))
    log.info("Database schema is up to date")
