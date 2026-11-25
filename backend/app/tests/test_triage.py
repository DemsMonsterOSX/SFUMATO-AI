"""Triage routing: pure functions (no database, no model)."""
from datetime import datetime, timezone

import pytest

from app.services import triage


def test_benign_needs_no_action():
    assert triage.route("benign", 5, 3, 0.4)["route"] == "no_action"


def test_attack_opens_a_high_incident():
    d = triage.route("attack", 5, 3, 0.4)
    assert d["route"] == "auto_attack" and d["severity"] == "high"


def test_unknown_but_concentrated_is_confirmed_by_the_rule():
    d = triage.route("unknown", 2000, 1, 1.0)
    assert d["route"] == "rule_confirmed" and d["severity"] == "high"


@pytest.mark.parametrize("n,n_dst,share", [(150, 1, 1.0), (2000, 80, 0.7), (2000, 1, 0.5)])
def test_unknown_not_concentrated_goes_to_a_human(n, n_dst, share):
    d = triage.route("unknown", n, n_dst, share)
    assert d["route"] == "human_queue" and d["severity"] == "low"


def test_invalid_stage1_is_rejected():
    with pytest.raises(ValueError):
        triage.route("maybe", 1, 1, 1.0)


def test_incident_payload_has_the_required_fields():
    d = triage.route("unknown", 2000, 1, 1.0)
    p = triage.build_incident("18.221.219.4", datetime(2018, 2, 14, 14, 40, tzinfo=timezone.utc),
                              {"n": 2000, "n_dst": 1, "n_dport": 1, "top_port_share": 1.0}, d, None, "172.31.69.25", 21)
    assert p["severity"] == "high" and p["network"]["destination_port"] == 21 and p["indicators"][0]["value"] == "18.221.219.4"
    assert p["incident_id"].startswith("triage-18.221.219.4-") and len(p["incident_id"]) <= 128
    assert triage.procedure_query(21).startswith("brute force ftp")
