"""Investigation worker: claims queued incidents from the database and runs the SOAR playbook.

Runs embedded in the API process (EMBEDDED_WORKER=true, default for local use) or as a dedicated
container (`python -m app.workers.worker`). Jobs whose heartbeat stops (crash, restart) are requeued
automatically up to MAX_JOB_ATTEMPTS.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.config import get_settings
from app.database.session import session_scope
from app.models import Incident
from app.services import events
from app.soar.engine import PlaybookAborted
from app.soar.tasks import InvestigationContext, build_engine

log = logging.getLogger("sfumato.worker")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


class Worker:
    def __init__(self, concurrency: int | None = None):
        s = get_settings()
        self.concurrency = concurrency or s.worker_concurrency
        self.worker_id = f"{socket.gethostname()}-{os.getpid()}"
        self._sem = asyncio.Semaphore(self.concurrency)
        self._stop = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self.processed = 0
        self.started_at = _now()

    def recover_stale(self) -> int:
        s = get_settings()
        limit = _now() - timedelta(seconds=s.job_stale_after_seconds)
        recovered: list[tuple[int, str]] = []
        with session_scope() as db:
            for inc in db.scalars(select(Incident).where(Incident.status == "running")):
                hb = _aware(inc.heartbeat_at) or _aware(inc.started_at)
                if hb and hb < limit:
                    if inc.attempts >= s.max_job_attempts:
                        inc.status, inc.error = "failed", "Worker stopped responding; maximum attempts reached"
                    else:
                        inc.status, inc.worker_id = "queued", None
                    recovered.append((inc.id, inc.status))
        for pk, status in recovered:  # emitted after commit: never write from two transactions at once
            events.emit(pk, "incident", f"Recovered stale investigation → {status}", status=status)
        return len(recovered)

    def claim(self) -> tuple[int, int] | None:
        with session_scope() as db:
            q = (select(Incident).where(Incident.status == "queued").order_by(Incident.created_at)
                 .limit(1).with_for_update(skip_locked=True))
            inc = db.scalars(q).first()
            if not inc:
                return None
            inc.status = "running"
            inc.worker_id = self.worker_id
            inc.attempts += 1
            inc.started_at = inc.started_at or _now()
            inc.heartbeat_at = _now()
            inc.error = None
            return inc.id, inc.attempts

    async def _heartbeat(self, pk: int) -> None:
        while True:
            await asyncio.sleep(10)
            with session_scope() as db:
                inc = db.get(Incident, pk)
                if inc is None or inc.status != "running":
                    return
                inc.heartbeat_at = _now()

    async def process(self, pk: int, attempt: int) -> None:
        with session_scope() as db:
            inc = db.get(Incident, pk)
            ctx = InvestigationContext(incident_pk=pk, incident_id=inc.incident_id, raw=inc.raw, cti_mode=inc.cti_mode)
        events.emit(pk, "incident", f"Investigation started by worker {self.worker_id}", status="running",
                    data={"attempt": attempt})
        hb = asyncio.create_task(self._heartbeat(pk))
        try:
            await build_engine().run(ctx, pk, attempt)
        except PlaybookAborted as e:
            self._fail(pk, str(e))
        except Exception as e:  # pragma: no cover - unexpected engine error
            log.exception("Investigation %s crashed", ctx.incident_id)
            self._fail(pk, f"{type(e).__name__}: {e}")
        finally:
            hb.cancel()
            self.processed += 1

    def _fail(self, pk: int, error: str) -> None:
        with session_scope() as db:
            inc = db.get(Incident, pk)
            inc.status = "failed"
            inc.error = error[:2000]
            inc.completed_at = _now()
        events.emit(pk, "incident", f"Investigation failed: {error}", status="failed")

    async def run_forever(self) -> None:
        s = get_settings()
        try:
            recovered = self.recover_stale()
            if recovered:
                log.info("Recovered %d stale investigation(s)", recovered)
        except Exception:
            log.exception("Stale job recovery failed")
        log.info("Worker %s started (concurrency %d)", self.worker_id, self.concurrency)
        last_recovery = _now()
        while not self._stop.is_set():
            try:
                await self._sem.acquire()
                job = await asyncio.to_thread(self.claim)
                if job is None:
                    self._sem.release()
                    await asyncio.sleep(s.worker_poll_interval)
                    if (_now() - last_recovery).total_seconds() > 60:
                        last_recovery = _now()
                        await asyncio.to_thread(self.recover_stale)
                    continue
                task = asyncio.create_task(self._run_job(*job))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
            except asyncio.CancelledError:
                break
            except Exception:  # database temporarily unavailable, etc.
                log.exception("Worker loop error; retrying in 3s")
                self._sem.release()
                await asyncio.sleep(3)

    async def _run_job(self, pk: int, attempt: int) -> None:
        try:
            await self.process(pk, attempt)
        finally:
            self._sem.release()

    async def stop(self) -> None:
        self._stop.set()
        for t in list(self._tasks):
            t.cancel()


def main() -> None:  # pragma: no cover - container entrypoint
    from app.core.logging import setup_logging
    from app.database.migrate import init_database
    from app.ml.inference import model_service

    setup_logging()
    init_database()
    model_service.load()
    asyncio.run(Worker().run_forever())


if __name__ == "__main__":  # pragma: no cover
    main()
