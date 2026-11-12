"""Pseudonymisation applied before anything is sent to an *external* LLM provider.

Usernames, hostnames, e-mail addresses, internal IPs/domains and file-system user paths are replaced
by stable placeholders (USER_1, HOST_1, …). The mapping never leaves the server.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
RE_USERPATH = re.compile(r"(?i)(c:\\users\\)([^\\\s\"']+)")


class Redactor:
    def __init__(self, sensitive: dict[str, list[str]]):
        self.map: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        for kind, values in sensitive.items():
            for v in values:
                if v:
                    self._token(kind, v)

    def _token(self, kind: str, value: str) -> str:
        key = value.lower()
        if key not in self.map:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.map[key] = f"{kind}_{self.counters[kind]}"
        return self.map[key]

    def text(self, s: str) -> str:
        for original in sorted(self.map, key=len, reverse=True):
            s = re.sub(re.escape(original), self.map[original], s, flags=re.IGNORECASE)
        s = RE_EMAIL.sub(lambda m: self._token("EMAIL", m.group(0)), s)
        s = RE_USERPATH.sub(lambda m: m.group(1) + self._token("USER", m.group(2)), s)

        def ip_sub(m: re.Match) -> str:
            try:
                ip = ipaddress.ip_address(m.group(0))
            except ValueError:
                return m.group(0)
            return self._token("INTERNAL_IP", m.group(0)) if (ip.is_private or ip.is_loopback) else m.group(0)

        return RE_IP.sub(ip_sub, s)

    def tree(self, v: Any) -> Any:
        if isinstance(v, dict):
            return {k: self.tree(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self.tree(x) for x in v]
        if isinstance(v, str):
            return self.text(v)
        return v


def build_redactor(incident: dict, indicators: list[dict]) -> Redactor:
    user = incident.get("user") or {}
    asset = incident.get("asset") or {}
    sensitive = {
        "USER": [user.get("username"), user.get("email")],
        "HOST": [asset.get("hostname"), asset.get("owner")],
        "DOMAIN": [i["value"] for i in indicators if i["type"] == "domain" and i["scope"] == "internal"]
                  + [user.get("domain")],
        "INTERNAL_IP": [i["value"] for i in indicators if i["type"] in ("ipv4", "ipv6") and i["scope"] in
                        ("private", "loopback", "link_local")],
    }
    return Redactor({k: [x for x in v if isinstance(x, str)] for k, v in sensitive.items()})
