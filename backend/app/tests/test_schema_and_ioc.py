import pytest
from pydantic import ValidationError

from app.schemas.incident import IncidentIn
from app.services import ioc
from app.tests.conftest import load_scenario

SPEC_EXAMPLE = {
    "incident_id": "SFUMATO-2026-0001", "timestamp": "2026-10-22T12:00:00Z", "source": "EDR", "severity": "high",
    "alert": {"name": "Suspicious PowerShell Execution",
              "description": "Suspicious PowerShell process launched from Microsoft Word", "category": "execution"},
    "asset": {"hostname": "WORKSTATION-042", "ip": "192.168.1.42", "criticality": "medium", "environment": "corporate"},
    "user": {"username": "demo.user"},
    "process": {"name": "powershell.exe", "parent": "winword.exe", "command_line": "powershell.exe -EncodedCommand <REDACTED>"},
    "network": {"destination_ip": "198.51.100.42", "destination_port": 443, "protocol": "HTTPS",
                "destination_domain": "example.org"},
    "indicators": [{"type": "ipv4", "value": "198.51.100.42"}, {"type": "domain", "value": "example.org"}],
    "metadata": {"detection_rule": "Suspicious PowerShell", "confidence": 75, "tags": ["powershell", "execution"]},
}


def test_spec_example_is_valid():
    inc = IncidentIn.model_validate(SPEC_EXAMPLE)
    assert inc.severity.value == "high" and inc.network.destination_port == 443


def test_optional_blocks_may_be_absent():
    minimal = {k: SPEC_EXAMPLE[k] for k in ("incident_id", "timestamp", "source", "severity", "alert")}
    inc = IncidentIn.model_validate(minimal)
    assert inc.process is None and inc.indicators == []


@pytest.mark.parametrize("mutate,field", [
    (lambda d: d.pop("alert"), "alert"),
    (lambda d: d.update(severity="urgent"), "severity"),
    (lambda d: d.update(unexpected="x"), "unexpected"),
    (lambda d: d.update(timestamp="2026-10-22T12:00:00"), "timestamp"),
    (lambda d: d.update(incident_id="bad id with spaces"), "incident_id"),
    (lambda d: d["network"].update(destination_port=70000), "destination_port"),
    (lambda d: d["indicators"].append({"type": "registry", "value": "x"}), "type"),
])
def test_schema_rejects_invalid(mutate, field):
    import copy

    d = copy.deepcopy(SPEC_EXAMPLE)
    mutate(d)
    with pytest.raises(ValidationError) as e:
        IncidentIn.model_validate(d)
    assert field in str(e.value)


def test_metadata_accepts_limited_extra_context():
    d = dict(SPEC_EXAMPLE, metadata={"confidence": 50, "ticket_system": "ServiceNow"})
    assert IncidentIn.model_validate(d).metadata.model_extra == {"ticket_system": "ServiceNow"}
    d = dict(SPEC_EXAMPLE, metadata={"nested": {"a": 1}})
    with pytest.raises(ValidationError):
        IncidentIn.model_validate(d)


@pytest.mark.parametrize("value,scope,shareable", [
    ("10.1.2.3", "private", False), ("192.168.1.42", "private", False), ("172.16.5.4", "private", False),
    ("127.0.0.1", "loopback", False), ("169.254.1.1", "link_local", False), ("100.64.1.1", "private", False),
    ("198.51.100.42", "documentation", False), ("203.0.113.66", "documentation", False),
    ("8.8.8.8", "public", True), ("224.0.0.1", "multicast", False),
])
def test_ip_classification(value, scope, shareable):
    inc = IncidentIn.model_validate(dict(SPEC_EXAMPLE, indicators=[{"type": "ipv4", "value": value}],
                                         network=None, asset=None))
    ind = next(i for i in ioc.extract_indicators(inc)["indicators"] if i["value"] == value)
    assert (ind["scope"], ind["shareable"]) == (scope, shareable)


def test_internal_and_reserved_domains_are_not_shareable():
    inc = IncidentIn.model_validate(dict(SPEC_EXAMPLE, network=None, indicators=[
        {"type": "domain", "value": "fileserver.corp"}, {"type": "domain", "value": "example.org"},
        {"type": "domain", "value": "evil.test"}, {"type": "domain", "value": "github.com"},
        {"type": "email", "value": "someone@github.com"}]))
    by = {i["value"]: i for i in ioc.extract_indicators(inc)["indicators"]}
    assert by["fileserver.corp"]["scope"] == "internal" and not by["fileserver.corp"]["shareable"]
    assert by["example.org"]["scope"] == "documentation" and not by["example.org"]["shareable"]
    assert not by["evil.test"]["shareable"]
    assert by["github.com"]["shareable"]
    assert not by["someone@github.com"]["shareable"]  # personal data never sent


def test_normalisation_refang_and_dedup():
    inc = IncidentIn.model_validate(dict(SPEC_EXAMPLE, network=None, asset=None, indicators=[
        {"type": "domain", "value": "EVIL[.]Example[.]com."}, {"type": "domain", "value": "evil.example.com"},
        {"type": "url", "value": "hxxp://evil.example.com/a"}, {"type": "sha256", "value": "Z" * 64}]))
    out = ioc.extract_indicators(inc)
    values = [i["value"] for i in out["indicators"]]
    assert values.count("evil.example.com") == 1
    assert "http://evil.example.com/a" in values
    assert out["rejected"] and out["rejected"][0]["type"] == "sha256"


def test_encoded_powershell_is_decoded_not_executed():
    inc = IncidentIn.model_validate(load_scenario("suspicious_powershell"))
    out = ioc.extract_indicators(inc)
    assert "DownloadString" in out["decoded_command"]
    assert any(i["value"] == "http://203.0.113.66/stage2.ps1" for i in out["indicators"])
