"""Lightweight SOAR engine: executes YAML playbooks as dependency graphs.

Features: concurrent branches, conditional nodes (`when`), per-node retry with exponential backoff,
timeouts, abort/continue failure policies, persisted task state (task_runs) and an execution journal
(investigation_events) that the dashboard streams in real time.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import yaml

from app.database.session import session_scope
from app.models import PlaybookRun, TaskRun
from app.services import events

log = logging.getLogger("sfumato.soar")


@dataclass
class RetryPolicy:
    max_attempts: int = 1
    backoff_seconds: float = 0.5


@dataclass
class NodeSpec:
    id: str
    name: str
    stage: int
    handler: str
    depends_on: list[str] = field(default_factory=list)
    when: str | None = None
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    timeout: float = 60
    on_failure: str = "abort"
    milestone: str | None = None


@dataclass
class Playbook:
    id: str
    version: str
    name: str
    description: str
    nodes: list[NodeSpec]
    remediation: str = "none"

    @classmethod
    def load(cls, path: Path) -> "Playbook":
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        nodes = []
        for n in data["nodes"]:
            retry = RetryPolicy(**(n.get("retry") or {}))
            nodes.append(NodeSpec(id=n["id"], name=n["name"], stage=int(n["stage"]), handler=n["handler"],
                                  depends_on=list(n.get("depends_on") or []), when=n.get("when"), retry=retry,
                                  timeout=float(n.get("timeout", 60)), on_failure=n.get("on_failure", "abort"),
                                  milestone=n.get("milestone")))
        pb = cls(id=data["id"], version=str(data["version"]), name=data["name"],
                 description=data.get("description", "").strip(), nodes=nodes,
                 remediation=data.get("remediation", "none"))
        pb.validate()
        return pb

    def validate(self) -> None:
        ids = {n.id for n in self.nodes}
        if len(ids) != len(self.nodes):
            raise ValueError("duplicate node ids")
        for n in self.nodes:
            missing = set(n.depends_on) - ids
            if missing:
                raise ValueError(f"node {n.id} depends on unknown nodes {missing}")
            if n.on_failure not in ("abort", "continue"):
                raise ValueError(f"node {n.id}: on_failure must be abort|continue")
        # cycle detection
        seen, stack = set(), set()
        graph = {n.id: n.depends_on for n in self.nodes}

        def visit(v):
            if v in stack:
                raise ValueError(f"cycle detected at {v}")
            if v in seen:
                return
            stack.add(v)
            for d in graph[v]:
                visit(d)
            stack.discard(v)
            seen.add(v)

        for v in graph:
            visit(v)

    def to_dict(self) -> dict:
        return {"id": self.id, "version": self.version, "name": self.name, "description": self.description,
                "remediation": self.remediation,
                "nodes": [{"id": n.id, "name": n.name, "stage": n.stage, "handler": n.handler,
                           "depends_on": n.depends_on, "when": n.when, "timeout": n.timeout,
                           "on_failure": n.on_failure, "milestone": n.milestone,
                           "retry": {"max_attempts": n.retry.max_attempts, "backoff_seconds": n.retry.backoff_seconds}}
                          for n in self.nodes]}


class PlaybookAborted(Exception):
    def __init__(self, node: str, error: str):
        super().__init__(f"Playbook aborted at node '{node}': {error}")
        self.node = node
        self.error = error


Handler = Callable[[Any, "TaskLogger"], Awaitable[dict | None]]
Predicate = Callable[[Any], bool]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _update_task(task_pk: int, **fields) -> None:
    with session_scope() as s:
        t = s.get(TaskRun, task_pk)
        for k, v in fields.items():
            setattr(t, k, v)


class TaskLogger:
    def __init__(self, incident_pk: int, node: NodeSpec):
        self.incident_pk = incident_pk
        self.node = node
        self.lines: list[dict] = []

    def __call__(self, message: str, level: str = "info", data: dict | None = None) -> None:
        self.lines.append({"ts": _now().isoformat(), "level": level, "message": message})
        events.emit(self.incident_pk, "log", message, stage=self.node.id, status=level, data=data)


class PlaybookEngine:
    def __init__(self, playbook: Playbook, handlers: dict[str, Handler], predicates: dict[str, Predicate]):
        missing = {n.handler for n in playbook.nodes} - set(handlers)
        if missing:
            raise ValueError(f"no handler registered for {missing}")
        self.playbook = playbook
        self.handlers = handlers
        self.predicates = predicates

    async def run(self, ctx: Any, incident_pk: int, attempt: int = 1) -> dict:
        pb = self.playbook
        with session_scope() as s:
            run = PlaybookRun(incident_pk=incident_pk, playbook=pb.id, playbook_version=pb.version, attempt=attempt)
            s.add(run)
            s.flush()
            task_pks = {}
            for order, n in enumerate(pb.nodes):
                t = TaskRun(run_id=run.id, node_id=n.id, name=n.name, order=order, status="pending", logs=[])
                s.add(t)
                s.flush()
                task_pks[n.id] = t.id
            run_id = run.id
        ctx.run_id = run_id
        events.emit(incident_pk, "playbook", f"Playbook {pb.id} v{pb.version} started (attempt {attempt})",
                    status="running", data={"run_id": run_id, "playbook": pb.to_dict()})
        t0 = time.perf_counter()
        state: dict[str, str] = {n.id: "pending" for n in pb.nodes}
        running: dict[str, asyncio.Task] = {}
        error: PlaybookAborted | None = None

        while True:
            if error is None:
                for n in pb.nodes:
                    if state[n.id] != "pending" or n.id in running:
                        continue
                    if all(state[d] in ("completed", "skipped", "failed") for d in n.depends_on):
                        running[n.id] = asyncio.create_task(self._execute(n, ctx, incident_pk, task_pks[n.id]))
            if not running:
                break
            done, _ = await asyncio.wait(running.values(), return_when=asyncio.FIRST_COMPLETED)
            for node_id, task in list(running.items()):
                if task not in done:
                    continue
                del running[node_id]
                try:
                    state[node_id] = task.result()
                except PlaybookAborted as e:
                    state[node_id] = "failed"
                    error = error or e
        if error:
            for n in pb.nodes:
                if state[n.id] == "pending":
                    state[n.id] = "cancelled"
                    _update_task(task_pks[n.id], status="cancelled")

        duration = int((time.perf_counter() - t0) * 1000)
        status = "failed" if error else "completed"
        with session_scope() as s:
            run = s.get(PlaybookRun, run_id)
            run.status = status
            run.completed_at = _now()
            run.duration_ms = duration
            run.error = str(error) if error else None
        events.emit(incident_pk, "playbook", f"Playbook {status} in {duration} ms", status=status,
                    data={"run_id": run_id, "duration_ms": duration, "states": state})
        if error:
            raise error
        return {"run_id": run_id, "duration_ms": duration, "states": state}

    async def _execute(self, n: NodeSpec, ctx: Any, incident_pk: int, task_pk: int) -> str:
        logger = TaskLogger(incident_pk, n)
        if n.when:
            pred = self.predicates.get(n.when)
            if pred is None or not pred(ctx):
                reason = f"condition '{n.when}' is false" if pred else f"unknown predicate '{n.when}'"
                _update_task(task_pk, status="skipped", logs=[{"ts": _now().isoformat(), "level": "info",
                                                               "message": f"Skipped: {reason}"}],
                             output={"skipped_reason": reason}, duration_ms=0)
                events.emit(incident_pk, "task", f"{n.name} skipped ({reason})", stage=n.id, status="skipped",
                            data={"node": n.id, "stage_no": n.stage})
                return "skipped"

        started = _now()
        t0 = time.perf_counter()
        last_error = ""
        for attempt in range(1, n.retry.max_attempts + 1):
            _update_task(task_pk, status="running", attempts=attempt, started_at=started)
            events.emit(incident_pk, "task", f"{n.name} started" + (f" (attempt {attempt})" if attempt > 1 else ""),
                        stage=n.id, status="running", data={"node": n.id, "stage_no": n.stage, "attempt": attempt})
            try:
                output = await asyncio.wait_for(self.handlers[n.handler](ctx, logger), timeout=n.timeout) or {}
                duration = int((time.perf_counter() - t0) * 1000)
                _update_task(task_pk, status="completed", completed_at=_now(), duration_ms=duration,
                             logs=logger.lines, output=output)
                events.emit(incident_pk, "task", f"{n.name} completed in {duration} ms", stage=n.id,
                            status="completed", data={"node": n.id, "stage_no": n.stage, "duration_ms": duration,
                                                      "output": output})
                if n.milestone:
                    events.milestone(incident_pk, n.milestone, data={"node": n.id, "output": output})
                return "completed"
            except asyncio.TimeoutError:
                last_error = f"timed out after {n.timeout:g}s"
            except PlaybookAborted:
                raise
            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"
                log.exception("Task %s failed", n.id)
            logger(f"Attempt {attempt} failed: {last_error}", level="error")
            if attempt < n.retry.max_attempts:
                delay = n.retry.backoff_seconds * (2 ** (attempt - 1))
                _update_task(task_pk, status="retrying", logs=logger.lines, error=last_error)
                events.emit(incident_pk, "task", f"{n.name} retrying in {delay:g}s", stage=n.id, status="retrying",
                            data={"node": n.id, "error": last_error})
                await asyncio.sleep(delay)

        duration = int((time.perf_counter() - t0) * 1000)
        _update_task(task_pk, status="failed", completed_at=_now(), duration_ms=duration, logs=logger.lines,
                     error=last_error)
        events.emit(incident_pk, "task", f"{n.name} failed: {last_error}", stage=n.id, status="failed",
                    data={"node": n.id, "stage_no": n.stage, "error": last_error, "policy": n.on_failure})
        if n.on_failure == "abort":
            raise PlaybookAborted(n.id, last_error)
        return "failed"
