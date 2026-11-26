#!/usr/bin/env python3
"""Creates the first Shuffle workflow: webhook trigger -> Shuffle Tools "repeat_back_to_me" (acknowledges the SFUMATO summary).

    python scripts/shuffle_setup.py <shuffle-ip>

Reads the API key from secrets/soar-secrets.txt (never printed). Prints the webhook URL. Idempotent by workflow name.
"""
import json
import ssl
import sys
import urllib.request
import uuid
from pathlib import Path

NAME = "SFUMATO incident notification"
ip = sys.argv[1]
base = f"https://{ip}:3443/api/v1"
sec = dict(l.split("=", 1) for l in (Path(__file__).resolve().parent.parent / "secrets" / "soar-secrets.txt").read_text().split())
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE


def call(method, path, body=None):
    req = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + sec["shuffle_apikey"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        raw = r.read().decode()
    return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw


wfs = call("GET", "/workflows")
wf = next((w for w in wfs if w.get("name") == NAME), None)
if not wf:
    wf = call("POST", "/workflows", {"name": NAME, "description": "Receives the SFUMATO investigation summary (verdict, score, human review) from the backend webhook."})
wid = wf["id"]
wf = call("GET", f"/workflows/{wid}")
tools = next((a for a in call("GET", "/apps") if a.get("name") == "Shuffle Tools"), None)
if not tools:
    sys.exit("Shuffle Tools app not found")
if not wf.get("actions"):
    aid = str(uuid.uuid4())
    wf["actions"] = [{"app_name": "Shuffle Tools", "app_version": tools.get("app_version", "1.2.0"), "app_id": tools["id"], "id": aid,
                      "name": "repeat_back_to_me", "label": "Acknowledge", "environment": "Shuffle", "is_valid": True, "isStartNode": True,
                      "position": {"x": 400, "y": 200}, "parameters": [{"name": "call", "value": "$exec"}], "errors": [], "authentication": [],
                      "execution_variable": {"description": "", "id": "", "name": "", "value": ""}}]
    wf["start"] = aid
if not wf.get("triggers"):
    tid = str(uuid.uuid4())
    wf["triggers"] = [{"app_name": "Webhook", "app_version": "1.0.0", "id": tid, "label": "SFUMATO", "name": "Webhook", "trigger_type": "WEBHOOK",
                       "status": "running", "environment": "Shuffle", "is_valid": True, "position": {"x": 100, "y": 200}, "errors": [],
                       "parameters": [{"name": "url", "value": f"{base}/hooks/webhook_{tid}"}, {"name": "tmp", "value": f"webhook_{tid}"},
                                      {"name": "auth_header", "value": ""}, {"name": "custom_response_body", "value": ""}]}]
    wf["branches"] = [{"id": str(uuid.uuid4()), "source_id": tid, "destination_id": wf["start"], "label": "", "has_errors": False, "conditions": []}]
    hook = call("POST", "/hooks/new", {"name": "SFUMATO", "type": "webhook", "id": tid, "workflow": wid, "start": wf["start"], "environment": "Shuffle",
                                       "auth": "", "custom_response": ""})
    print("hook:", str(hook)[:120])
wf["is_valid"] = True
saved = call("PUT", f"/workflows/{wid}", wf)
print("workflow", wid, "saved:", str(saved)[:120])
hook_id = wf["triggers"][0]["id"]
print("WEBHOOK_URL=" + f"https://{ip}:3443/api/v1/hooks/webhook_{hook_id}")
