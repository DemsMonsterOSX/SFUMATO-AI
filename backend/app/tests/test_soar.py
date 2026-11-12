import asyncio
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.database.session import session_scope
from app.models import Incident, PlaybookRun
from app.services import events
from app.soar.engine import NodeSpec, Playbook, PlaybookAborted, PlaybookEngine, RetryPolicy
from app.soar.tasks import PLAYBOOK


def _incident(iid: str) -> int:
    with session_scope() as s:
        inc = Incident(incident_id=iid, source="test", severity="low", alert_name="t",
                       alert_timestamp=datetime.now(timezone.utc), raw={}, cti_mode="demo", submitted_via="test",
                       status="running")
        s.add(inc)
        s.flush()
        return inc.id


class Ctx:
    run_id = None
    flag = False


def _pb(nodes):
    pb = Playbook(id="TEST", version="1", name="t", description="", nodes=nodes)
    pb.validate()
    return pb


def test_branching_retry_and_parallel_execution():
    calls = {"flaky": 0, "order": []}

    async def ok(ctx, log):
        log("ok")
        calls["order"].append("ok")
        return {"ok": True}

    async def flaky(ctx, log):
        calls["flaky"] += 1
        if calls["flaky"] < 2:
            raise RuntimeError("transient")
        return {"attempts": calls["flaky"]}

    async def slow(ctx, log):
        await asyncio.sleep(0.2)
        return {}

    nodes = [
        NodeSpec("a", "A", 1, "ok"),
        NodeSpec("b", "B", 2, "flaky", ["a"], retry=RetryPolicy(3, 0.01)),
        NodeSpec("c", "C", 2, "slow", ["a"]),
        NodeSpec("d", "D", 3, "ok", ["b", "c"], when="flag_set"),
        NodeSpec("e", "E", 4, "ok", ["d"]),
    ]
    engine = PlaybookEngine(_pb(nodes), {"ok": ok, "flaky": flaky, "slow": slow}, {"flag_set": lambda c: c.flag})
    pk = _incident("SOAR-T1")
    res = asyncio.run(engine.run(Ctx(), pk))
    assert res["states"] == {"a": "completed", "b": "completed", "c": "completed", "d": "skipped", "e": "completed"}
    assert calls["flaky"] == 2
    with session_scope() as s:
        run = s.scalars(select(PlaybookRun).where(PlaybookRun.incident_pk == pk)).one()
        tasks = {t.node_id: t for t in run.tasks}
        assert tasks["b"].attempts == 2 and tasks["b"].status == "completed"
        assert tasks["d"].status == "skipped" and tasks["a"].logs[0]["message"] == "ok"
        assert all(t.duration_ms is not None for t in run.tasks)
    types = [e["type"] for e in events.list_events(pk)]
    assert "task" in types and "log" in types and types[0] == "playbook"


def test_failure_policies_and_timeout():
    async def boom(ctx, log):
        raise ValueError("nope")

    async def hang(ctx, log):
        await asyncio.sleep(5)

    async def ok(ctx, log):
        return {}

    # continue: dependants still run
    pb = _pb([NodeSpec("x", "X", 1, "boom", on_failure="continue"), NodeSpec("y", "Y", 2, "ok", ["x"])])
    res = asyncio.run(PlaybookEngine(pb, {"boom": boom, "ok": ok}, {}).run(Ctx(), _incident("SOAR-T2")))
    assert res["states"] == {"x": "failed", "y": "completed"}

    # abort: the playbook stops, pending nodes are cancelled
    pb = _pb([NodeSpec("x", "X", 1, "hang", timeout=0.1), NodeSpec("y", "Y", 2, "ok", ["x"])])
    pk = _incident("SOAR-T3")
    with pytest.raises(PlaybookAborted) as e:
        asyncio.run(PlaybookEngine(pb, {"hang": hang, "ok": ok}, {}).run(Ctx(), pk))
    assert "timed out" in e.value.error
    with session_scope() as s:
        run = s.scalars(select(PlaybookRun).where(PlaybookRun.incident_pk == pk)).one()
        assert run.status == "failed" and {t.node_id: t.status for t in run.tasks} == {"x": "failed", "y": "cancelled"}


def test_playbook_validation_rejects_cycles_and_unknown_dependencies():
    with pytest.raises(ValueError):
        _pb([NodeSpec("a", "A", 1, "h", ["b"]), NodeSpec("b", "B", 1, "h", ["a"])])
    with pytest.raises(ValueError):
        _pb([NodeSpec("a", "A", 1, "h", ["missing"])])


def test_main_playbook_definition():
    pb = PLAYBOOK()
    assert pb.id == "SFUMATO_AUTONOMOUS_INVESTIGATION" and pb.remediation == "none"
    assert len({n.stage for n in pb.nodes}) == 16  # the 16 stages of the specification
    by = {n.id: n for n in pb.nodes}
    # CTI enrichment and behavioural analysis are independent branches (run concurrently)
    assert by["query_cti"].depends_on == ["classify_assets"] == by["analyze_behavior"].depends_on
    assert by["query_cti"].when == "has_queryable_indicators"
