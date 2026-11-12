"""Indicator extraction, normalisation, de-duplication and scope classification.

Nothing extracted here is ever executed. Encoded PowerShell payloads are only *decoded* so that
embedded URLs/domains can be analysed as text.
"""
from __future__ import annotations

import base64
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from app.core.config import get_settings
from app.schemas.evidence import ExtractedIndicator
from app.schemas.incident import IncidentIn

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
SHARED_NETS = [ipaddress.ip_network("100.64.0.0/10")]
RESERVED_TLDS = {"test", "example", "invalid", "localhost", "onion", "local", "home.arpa"}
RESERVED_DOMAINS = {"example.com", "example.org", "example.net"}

RE_URL = re.compile(r"\b(?:https?|hxxps?)://[^\s'\"<>`)|;,]+", re.IGNORECASE)
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
RE_HASH = {"md5": re.compile(r"^[a-f0-9]{32}$"), "sha1": re.compile(r"^[a-f0-9]{40}$"),
           "sha256": re.compile(r"^[a-f0-9]{64}$")}
RE_ENCODED = re.compile(r"-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand|ec)\s+([A-Za-z0-9+/=]{16,})",
                        re.IGNORECASE)
RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def refang(value: str) -> str:
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    return v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[dot]", ".")


def decode_powershell(command_line: str | None) -> str | None:
    """Decode a PowerShell -EncodedCommand argument (UTF-16LE base64) for *static* inspection only."""
    if not command_line:
        return None
    m = RE_ENCODED.search(command_line)
    if not m:
        return None
    blob = m.group(1)
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        text = raw.decode("utf-16-le", errors="strict")
    except Exception:
        try:
            text = raw.decode("utf-8", errors="strict")  # type: ignore[possibly-undefined]
        except Exception:
            return None
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")
    return text[:4000] if text.strip() else None


def classify_ip(value: str) -> tuple[str, str | None]:
    ip = ipaddress.ip_address(value)
    if any(ip in n for n in DOC_NETS):
        return "documentation", "RFC 5737/3849 documentation range"
    if ip.is_loopback:
        return "loopback", None
    if ip.is_link_local:
        return "link_local", None
    if ip.is_multicast:
        return "multicast", None
    if any(ip in n for n in SHARED_NETS):
        return "private", "RFC 6598 shared address space"
    if ip.is_private:
        return "private", "RFC 1918 / private address"
    if ip.is_reserved or ip.is_unspecified or not ip.is_global:
        return "reserved", None
    return "public", None


def classify_domain(value: str, internal_hints: set[str]) -> tuple[str, str | None]:
    d = value.lower().rstrip(".")
    settings = get_settings()
    if any(d.endswith(sfx) for sfx in settings.internal_suffixes) or "." not in d:
        return "internal", "internal domain suffix"
    if any(d == h or d.endswith("." + h) for h in internal_hints):
        return "internal", "matches the organisation's domain"
    tld = d.rsplit(".", 1)[-1]
    if tld in RESERVED_TLDS or d in RESERVED_DOMAINS or any(d.endswith("." + r) for r in RESERVED_DOMAINS):
        return "documentation", "reserved for documentation/testing (RFC 2606/6761)"
    return "public", None


def normalize(type_: str, value: str) -> tuple[str, str] | None:
    """Return (type, canonical value) or None if the value is not a valid indicator of that type."""
    v = refang(value)
    t = type_.lower()
    try:
        if t in ("ipv4", "ipv6"):
            ip = ipaddress.ip_address(v)
            return ("ipv4" if ip.version == 4 else "ipv6"), str(ip)
        if t in ("domain", "hostname"):
            d = v.lower().rstrip(".")
            if RE_DOMAIN.match(d):
                return "domain", d
            if t == "hostname" and re.match(r"^[a-z0-9-]{1,63}$", d):
                return "hostname", d
            return None
        if t == "url":
            parts = urlsplit(v)
            if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
                return None
            netloc = parts.netloc.lower()
            return "url", urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
        if t in RE_HASH:
            h = v.lower()
            return (t, h) if RE_HASH[t].match(h) else None
        if t == "cve":
            return ("cve", v.upper()) if RE_CVE.fullmatch(v) else None
        if t == "email":
            return ("email", v.lower()) if RE_EMAIL.match(v) else None
    except ValueError:
        return None
    return None


def guess_hash_type(value: str) -> str | None:
    h = value.lower()
    for t, rx in RE_HASH.items():
        if rx.match(h):
            return t
    return None


class _Collector:
    def __init__(self, internal_hints: set[str]):
        self.items: dict[tuple[str, str], ExtractedIndicator] = {}
        self.rejected: list[dict] = []
        self.internal_hints = internal_hints

    def add(self, type_: str, value: str | None, origin: str) -> None:
        if not value:
            return
        norm = normalize(type_, value)
        if norm is None:
            self.rejected.append({"type": type_, "value": value[:200], "origin": origin})
            return
        t, v = norm
        key = (t, v)
        if key in self.items:
            if origin not in self.items[key].origins:
                self.items[key].origins.append(origin)
            return
        scope, note, shareable = self._scope(t, v)
        self.items[key] = ExtractedIndicator(value=v, type=t, scope=scope, shareable=shareable,
                                             origins=[origin], note=note)
        if t == "url":  # the host of a URL is an indicator in its own right
            host = urlsplit(v).hostname or ""
            try:
                ipaddress.ip_address(host)
                self.add("ipv4" if ":" not in host else "ipv6", host, f"{origin}.host")
            except ValueError:
                self.add("domain", host, f"{origin}.host")

    def _scope(self, t: str, v: str) -> tuple[str, str | None, bool]:
        if t in ("ipv4", "ipv6"):
            scope, note = classify_ip(v)
            return scope, note, scope == "public"
        if t == "domain":
            scope, note = classify_domain(v, self.internal_hints)
            return scope, note, scope == "public"
        if t == "hostname":
            return "internal", "single-label hostname", False
        if t == "url":
            scope, note = self._url_scope(v)
            return scope, note, scope == "public"
        if t == "email":
            return "unknown", "e-mail addresses are personal data and never sent to public CTI", False
        return "public", None, True  # hashes and CVEs carry no internal information

    def _url_scope(self, v: str) -> tuple[str, str | None]:
        host = urlsplit(v).hostname or ""
        try:
            ipaddress.ip_address(host)
            return classify_ip(host)
        except ValueError:
            return classify_domain(host, self.internal_hints)


def extract_indicators(incident: IncidentIn) -> dict:
    hints: set[str] = set()
    if incident.user and incident.user.domain and "." in incident.user.domain:
        hints.add(incident.user.domain.lower())
    if incident.user and incident.user.email and "@" in incident.user.email:
        hints.add(incident.user.email.split("@", 1)[1].lower())

    c = _Collector(hints)
    for i, ind in enumerate(incident.indicators):
        c.add(ind.type.value, ind.value, f"indicators[{i}]")

    n = incident.network
    if n:
        c.add("ipv4", n.destination_ip, "network.destination_ip")
        c.add("ipv4", n.source_ip, "network.source_ip")
        c.add("domain", n.destination_domain, "network.destination_domain")
        c.add("url", n.url, "network.url")
    if incident.asset and incident.asset.ip:
        c.add("ipv4", incident.asset.ip, "asset.ip")
    if incident.authentication and incident.authentication.source_ip:
        c.add("ipv4", incident.authentication.source_ip, "authentication.source_ip")
    for origin, h in (("process.sha256", incident.process and incident.process.sha256),
                      ("file.sha256", incident.file and incident.file.sha256),
                      ("file.md5", incident.file and incident.file.md5)):
        if h:
            c.add(guess_hash_type(h) or "sha256", h, origin)

    texts = {
        "alert.description": incident.alert.description or "",
        "process.command_line": (incident.process.command_line if incident.process else "") or "",
    }
    decoded = decode_powershell(texts["process.command_line"])
    if decoded:
        texts["process.command_line(decoded)"] = decoded
    for origin, text in texts.items():
        for m in RE_URL.findall(text):
            c.add("url", m.rstrip(".,;"), origin)
        for m in RE_CVE.findall(text):
            c.add("cve", m, origin)
        for m in RE_IPV4.findall(text):
            c.add("ipv4", m, origin)

    # IP-literal values declared as ipv4 but actually ipv6 are fixed by normalize(); keep stable ordering.
    items = sorted(c.items.values(), key=lambda x: (not x.shareable, x.type, x.value))
    return {"indicators": [i.model_dump() for i in items], "rejected": c.rejected, "decoded_command": decoded}
