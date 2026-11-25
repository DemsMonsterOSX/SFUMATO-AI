"""Pure parts of the live architecture view."""
from app.services import gce


def test_vcpus_of_predefined_and_shared_core_types():
    assert gce.vcpus("e2-standard-8") == 8
    assert gce.vcpus("n1-standard-4") == 4
    assert gce.vcpus("e2-small") == 2
    assert gce.vcpus("custom") is None


def test_not_live_outside_google_cloud(monkeypatch):
    class Boom:
        def __init__(self, *a, **k): ...
        def __enter__(self): raise OSError("no metadata server")
        def __exit__(self, *a): ...
    monkeypatch.setattr(gce.httpx, "Client", Boom)
    out = gce._fetch()
    assert out["live"] is False and "Compute API" in out["reason"]
