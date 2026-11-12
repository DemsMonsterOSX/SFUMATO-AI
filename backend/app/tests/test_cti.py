import asyncio

import httpx
import pytest
import respx

from app.core.cache import cache
from app.core.config import get_settings
from app.cti import engine
from app.cti.abusech import THREATFOX_URL, URLHAUS_URL, ThreatFox, URLhaus
from app.cti.base import ProviderError
from app.cti.cisa_kev import CisaKEV
from app.cti.correlation import correlate
from app.cti.opencti import OpenCTI
from app.cti.otx import OTX
from app.schemas.evidence import ExtractedIndicator
from app.services.evidence import EvidenceBook


def ind(value, type_="ipv4", scope="public", shareable=True):
    return ExtractedIndicator(value=value, type=type_, scope=scope, shareable=shareable, origins=["test"])


# --------------------------------------------------------------------------- parsers (real response formats)
def test_threatfox_parse():
    p = ThreatFox({"abusech_auth_key": "k"})
    hit = p.parse("ipv4", "1.2.3.4", {"query_status": "ok", "data": [
        {"id": "1", "ioc": "1.2.3.4:443", "threat_type_desc": "C&C", "malware_printable": "AsyncRAT",
         "confidence_level": 75, "first_seen": "2026-10-01 10:00:00 UTC", "last_seen": None, "tags": ["rat"],
         "reference": None}]})
    assert hit["verdict"] == "malicious" and hit["malware"] == ["AsyncRAT"] and hit["confidence"] == 75
    assert p.parse("ipv4", "1.2.3.4", {"query_status": "no_result", "data": "..."})["verdict"] == "not_found"
    with pytest.raises(ProviderError):
        p.parse("ipv4", "1.2.3.4", {"query_status": "illegal_search_term"})


def test_urlhaus_parse_host_and_url():
    p = URLhaus({"abusech_auth_key": "k"})
    host = p.parse("domain", "bad.com", {"query_status": "ok", "url_count": "2", "blacklists": {"spamhaus_dbl": "not listed"},
                                        "urls": [{"url_status": "offline", "date_added": "2026-01-01 00:00:00 UTC", "tags": []}]})
    assert host["verdict"] == "suspicious"  # only historical, offline URLs
    url = p.parse("url", "http://bad.com/x", {"query_status": "ok", "url_status": "online", "threat": "malware_download",
                                             "payloads": [{"signature": "Emotet"}], "tags": ["exe"]})
    assert url["verdict"] == "malicious" and url["malware"] == ["Emotet"]
    assert p.parse("domain", "x.com", {"query_status": "no_results"})["verdict"] == "not_found"


def test_otx_parse_never_turns_unknown_into_benign():
    p = OTX({"otx_api_key": "k"})
    assert p.parse("domain", "x.com", {"pulse_info": {"count": 0, "pulses": []}, "validation": []})["verdict"] == "not_found"
    allow = p.parse("domain", "google.com", {"pulse_info": {"count": 0}, "validation": [{"source": "whitelist", "name": "x"}]})
    assert allow["verdict"] == "allowlisted"
    many = p.parse("ipv4", "1.2.3.4", {"pulse_info": {"count": 4, "pulses": [
        {"id": "a", "name": "p", "malware_families": [{"display_name": "Mirai"}], "attack_ids": [{"id": "T1110"}],
         "adversary": "", "tags": ["iot"], "created": "2026-01-01T00:00:00", "modified": "2026-02-01T00:00:00"}]}})
    assert many["verdict"] == "malicious" and many["mitre"] == ["T1110"] and many["malware"] == ["Mirai"]


def test_kev_and_opencti_parse():
    kev = CisaKEV({}).parse("cve", "CVE-2023-4966", {"catalogVersion": "x", "match": {
        "cveID": "CVE-2023-4966", "vulnerabilityName": "Citrix Bleed", "dateAdded": "2023-10-18",
        "knownRansomwareCampaignUse": "Known", "vendorProject": "Citrix", "product": "NetScaler"}})
    assert kev["verdict"] == "malicious" and "ransomware-campaign-use" in kev["tags"]
    oc = OpenCTI({"opencti_url": "http://x", "opencti_token": "t"}).parse("ipv4", "1.2.3.4", {"data": {
        "stixCyberObservables": {"edges": [{"node": {"observable_value": "1.2.3.4", "x_opencti_score": 80,
                                                      "objectLabel": [{"value": "c2"}],
                                                      "stixCoreRelationships": {"edges": [{"node": {
                                                          "relationship_type": "communicates-with",
                                                          "to": {"entity_type": "Malware", "name": "Qakbot"}}}]}}}]},
        "indicators": {"edges": []}}})
    assert oc["verdict"] == "malicious" and oc["malware"] == ["Qakbot"] and oc["relationships"]


# --------------------------------------------------------------------------- engine: privacy, failures, modes
@pytest.fixture
def live_keys(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "abuse-key")
    monkeypatch.setenv("OTX_API_KEY", "otx-key")
    get_settings.cache_clear()
    cache._mem.clear()
    yield
    get_settings.cache_clear()
    cache._mem.clear()


def test_private_and_documentation_indicators_never_sent_live(live_keys):
    with respx.mock(assert_all_called=False) as m:
        route_tf = m.post(THREATFOX_URL).mock(return_value=httpx.Response(200, json={"query_status": "no_result", "data": ""}))
        route_uh = m.post(url__startswith=URLHAUS_URL).mock(return_value=httpx.Response(200, json={"query_status": "no_results"}))
        route_otx = m.get(url__startswith="https://otx.alienvault.com").mock(
            return_value=httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}}))
        inds = [ind("10.0.0.5", scope="private", shareable=False),
                ind("198.51.100.42", scope="documentation", shareable=False), ind("8.8.8.8")]
        out = asyncio.run(engine.enrich(inds, "live"))
    sent = [str(c.request.url) + (c.request.content or b"").decode() for r in (route_tf, route_uh, route_otx) for c in r.calls]
    assert sent, "the public indicator should have been queried"
    assert not any("10.0.0.5" in s or "198.51.100.42" in s for s in sent)
    assert all(r.indicator == "8.8.8.8" for r in out["results"])
    assert {s["indicator"] for s in out["skipped"]} == {"10.0.0.5", "198.51.100.42"}
    # the API key is sent as a header, never stored in the raw response
    assert route_tf.calls[0].request.headers["Auth-Key"] == "abuse-key"
    assert all("abuse-key" not in str(r.raw) for r in out["results"])


def test_provider_failures_are_isolated(live_keys):
    with respx.mock(assert_all_called=False) as m:
        m.post(THREATFOX_URL).mock(side_effect=httpx.ConnectTimeout("boom"))
        m.post(url__startswith=URLHAUS_URL).mock(return_value=httpx.Response(401, json={}))
        m.get(url__startswith="https://otx.alienvault.com").mock(return_value=httpx.Response(503))
        out = asyncio.run(engine.enrich([ind("8.8.4.4")], "live"))
    by = {r.provider: r for r in out["results"]}
    assert by["threatfox"].status == "timeout"  # retried, then reported as a timeout
    assert by["urlhaus"].status == "unauthorized"
    assert by["otx"].status == "error"  # 503 retried, then reported
    assert all(r.verdict == "unknown" for r in by.values())
    assert out["coverage"] == 0.0


def test_unconfigured_providers_are_not_queried_live():
    out = asyncio.run(engine.enrich([ind("8.8.4.4")], "live"))
    assert out["results"] == []  # no keys in the test environment; KEV only handles CVEs
    assert all(not p["configured"] or p["key"] == "cisa_kev" for p in out["providers"])


def test_demo_mode_uses_labelled_fixtures_through_same_parsers():
    out = asyncio.run(engine.enrich([ind("203.0.113.66", scope="documentation", shareable=False)], "demo"))
    assert out["results"] and all(r.data_origin == "demo_fixture" for r in out["results"])
    assert {r.provider for r in out["results"] if r.verdict == "malicious"} >= {"threatfox", "urlhaus", "opencti"}


def test_correlation_unknown_is_neutral_not_benign():
    out = asyncio.run(engine.enrich([ind("telemetry-sync.example", "domain", "documentation", False)], "demo"))
    book = EvidenceBook()
    correlate(out["results"], book)
    ev = book.all()
    assert len(ev) == 1 and ev[0].polarity == "neutral" and ev[0].kind == "cti_not_found"
