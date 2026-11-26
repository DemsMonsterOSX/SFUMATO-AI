"""Scale-out / scale-in decisions of the scorer autoscaler (pure function, no Kafka, no Google Cloud)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "streaming"))
from autoscaler import decide  # noqa: E402

KW = dict(out_lag=3000, in_lag=300, out_hold=20, in_hold=240, cooldown=90)


def test_adds_a_worker_only_after_the_backlog_stays_high():
    s = {}
    assert decide(s, 100, 5000, 0, 2, **KW) is None          # first sight: starts the timer
    assert decide(s, 110, 5200, 0, 2, **KW) is None          # 10 s: not long enough
    assert decide(s, 121, 6000, 0, 2, **KW) == "out"         # 21 s: scale out


def test_a_short_spike_does_not_scale():
    s = {}
    decide(s, 100, 9000, 0, 2, **KW)
    assert decide(s, 105, 100, 0, 2, **KW) is None           # backlog gone: timer reset
    assert decide(s, 130, 9000, 0, 2, **KW) is None         # new spike, timer restarts


def test_never_exceeds_the_number_of_workers():
    s = {}
    decide(s, 100, 9000, 2, 2, **KW)
    assert decide(s, 200, 9000, 2, 2, **KW) is None


def test_cooldown_between_two_actions():
    s = {}
    decide(s, 100, 9000, 0, 2, **KW)
    assert decide(s, 125, 9000, 0, 2, **KW) == "out"
    decide(s, 126, 9000, 1, 2, **KW)
    assert decide(s, 150, 9000, 1, 2, **KW) is None          # 25 s after the last action: cooling down
    assert decide(s, 220, 9000, 1, 2, **KW) == "out"


def test_removes_a_worker_after_a_quiet_period():
    s = {}
    assert decide(s, 100, 10, 2, 2, **KW) is None
    assert decide(s, 300, 10, 2, 2, **KW) is None            # 200 s < 240 s
    assert decide(s, 345, 10, 2, 2, **KW) == "in"


def test_no_scale_in_without_workers_and_none_between_thresholds():
    s = {}
    decide(s, 100, 10, 0, 2, **KW)
    assert decide(s, 1000, 10, 0, 2, **KW) is None           # nothing to remove
    assert decide(s, 1001, 1000, 1, 2, **KW) is None        # between the thresholds: hold
