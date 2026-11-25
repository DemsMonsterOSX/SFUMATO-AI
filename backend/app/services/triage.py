"""Triage of a per-source detection window: what to do with a verdict that may be "I do not know".

The detector (bigdata/open_set.py) answers attack, benign or unknown for one source in one 60-second window. This module is the
decision part that runs in the application, with no machine-learning dependency:

  attack    -> open an incident right away (the detector and its ensemble agree)
  benign    -> nothing to do
  unknown   -> stage 2: the concentration rule (many connections, at most 2 hosts, one dominant port) confirms an attack on
               behaviour alone; if it does not fire, the window goes to the human queue as a low-severity incident to review

Each opened incident carries the response procedure that best matches the target port (procedure library, BM25 search), so the
analyst starts from a runbook. Procedures are unvalidated AI drafts: say so wherever they are shown.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.services import procedures as proc_lib

ROUTES = ("auto_attack", "rule_confirmed", "human_queue", "no_action")
AUTH_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 3389: "rdp", 445: "smb"}
WEB_PORTS = {80, 443, 8080, 8443}


def concentration_rule(n: int, n_dst: int, top_port_share: float) -> bool:
    """200 or more connections from one source in a minute, to at most 2 hosts, at least 90 % on one port."""
    return n >= 200 and n_dst <= 2 and top_port_share >= 0.9


def route(stage1: str, n: int, n_dst: int, top_port_share: float) -> dict[str, Any]:
    if stage1 not in ("attack", "benign", "unknown"):
        raise ValueError("stage1 must be attack, benign or unknown")
    if stage1 == "benign":
        return {"route": "no_action", "severity": None, "reason": "the detector sees nothing unusual"}
    if stage1 == "attack":
        return {"route": "auto_attack", "severity": "high", "reason": "the detector and its ensemble agree this is an attack"}
    if concentration_rule(n, n_dst, top_port_share):
        return {"route": "rule_confirmed", "severity": "high",
                "reason": "the detector does not know this behaviour, but the source hammers one target: concentration rule fired"}
    return {"route": "human_queue", "severity": "low",
            "reason": "unknown behaviour and no rule confirms it: an analyst must decide (this is what the detector admits it cannot judge)"}


def procedure_query(dst_port: int | None) -> str:
    if dst_port in AUTH_PORTS:
        return f"brute force {AUTH_PORTS[dst_port]} credential attack"
    if dst_port in WEB_PORTS:
        return "web denial of service http flood"
    return "network scan reconnaissance suspicious connections"


def suggest_procedure(dst_port: int | None) -> dict | None:
    if not proc_lib.available():
        return None
    hits = proc_lib.search(procedure_query(dst_port), 1)
    if not hits:
        return None
    h = hits[0]
    return {"id": h.get("id"), "title": h.get("title"), "tactic": h.get("tactic"), "draft": True}


def build_incident(src: str, window_start: datetime, stats: dict, decision: dict, procedure: dict | None, dst_ip: str | None, dst_port: int | None) -> dict:
    """Payload in the platform's incident format (schemas/incident.py), ready for ingestion.submit."""
    ts = window_start if window_start.tzinfo else window_start.replace(tzinfo=timezone.utc)
    stamp = ts.strftime("%Y%m%dT%H%M%S")
    tags = ["per-source-window", decision["route"]]
    meta: dict[str, Any] = {"detection_rule": "concentration_rule" if decision["route"] == "rule_confirmed" else "open_set_detector",
                            "tags": tags, "window_seconds": 60, "connections": int(stats["n"]), "distinct_hosts": int(stats["n_dst"]),
                            "distinct_ports": int(stats["n_dport"]), "top_port_share": round(float(stats["top_port_share"]), 3),
                            "triage_reason": decision["reason"]}
    if procedure:
        meta["suggested_procedure"] = f'{procedure["id"]}: {procedure["title"]} (AI draft, not validated)'
    payload: dict[str, Any] = {
        "incident_id": f"triage-{src}-{stamp}".replace(":", "-")[:128],
        "timestamp": ts.isoformat(),
        "source": "sfumato-open-set-detector",
        "severity": decision["severity"],
        "alert": {"name": {"auto_attack": "Concentrated connections from one source (detector verdict: attack)",
                           "rule_confirmed": "Concentrated connections from one source (unknown to the detector, confirmed by rule)",
                           "human_queue": "Unknown source behaviour needs analyst review"}[decision["route"]],
                  "description": decision["reason"], "category": "network"},
        "network": {"source_ip": src, "protocol": "tcp", "direction": "inbound"},
        "indicators": [{"type": "ipv4", "value": src}],
        "metadata": meta,
    }
    if dst_ip:
        payload["network"]["destination_ip"] = dst_ip
    if dst_port is not None:
        payload["network"]["destination_port"] = int(dst_port)
    return payload
