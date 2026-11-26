"""Notifies the external open-source SOAR (Shuffle) when an investigation finishes (fire and forget).

Enabled only when SHUFFLE_WEBHOOK_URL is set (the URL of a Shuffle workflow webhook trigger). The payload is a small summary,
never the raw incident. Failures are swallowed: the SFUMATO investigation must never depend on the external SOAR.
"""
from __future__ import annotations

import json
import os
import threading
import urllib.request


def enabled() -> bool:
    return bool(os.environ.get("SHUFFLE_WEBHOOK_URL"))


def build_payload(incident_id: str, status: str, decision: dict, duration_ms: int) -> dict:
    return {
        "source": "sfumato",
        "incident_id": incident_id,
        "status": status,
        "verdict": decision.get("verdict"),
        "threat_score": decision.get("threat_score"),
        "confidence": decision.get("confidence"),
        "human_review_required": bool(decision.get("human_review_required")),
        "duration_ms": duration_ms,
    }


def _post(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(url, data=json.dumps(payload, default=str).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
    except Exception:
        pass


def notify(incident_id: str, status: str, decision: dict, duration_ms: int) -> bool:
    """Returns True when a notification was handed to the sender thread."""
    if not enabled():
        return False
    payload = build_payload(incident_id, status, decision, duration_ms)
    threading.Thread(target=_post, args=(os.environ["SHUFFLE_WEBHOOK_URL"], payload), name="shuffle-notify", daemon=True).start()
    return True
