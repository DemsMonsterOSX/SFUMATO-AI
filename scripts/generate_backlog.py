#!/usr/bin/env python3
"""Generate a backlog of alerts and have Sfumato investigate them through the normal REST API.

Each alert is a variation of a bundled scenario (other hosts, users, times, values). Nothing is
pre-computed: every alert is queued and investigated by the real pipeline (SOAR, CTI, ML, AI, verdict).

    python scripts/generate_backlog.py --count 40 --wait
    python scripts/generate_backlog.py --api http://localhost:8000 --key <API key> --hours 48 --cti-mode demo

Standard library only, so it runs outside the backend virtual environment.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "examples" / "incidents"

USERS = ["a.dupont", "c.bernard", "j.martin", "l.moreau", "m.petit", "s.roux", "t.garcia", "n.fournier",
         "e.girard", "p.lambert", "h.mercier", "r.blanc"]
DEPARTMENTS = ["Finance", "Sales", "Marketing", "HR", "Legal", "Engineering", "Support"]
COUNTRIES = ["BR", "US", "NL", "SG", "DE", "IN", "ZA"]
RARE_DOMAINS = ["telemetry-sync.example", "cdn-metrics.example", "update-check.example", "img-cache.example",
                "status-ping.example", "fonts-mirror.example"]

# relative frequency: most SOC alerts are benign or low-signal
WEIGHTS = {
    "known_benign_software": 22, "insufficient_evidence": 16, "legitimate_admin": 14,
    "suspicious_authentication": 14, "suspicious_powershell": 10, "malicious_domain": 10,
    "php_cgi_exploit": 8, "prompt_injection": 6,
}


def load_templates() -> dict[str, dict]:
    index = json.loads((SCENARIOS / "index.json").read_text(encoding="utf-8"))
    return {s["key"]: json.loads((SCENARIOS / s["file"]).read_text(encoding="utf-8")) for s in index}


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def workstation(rng: random.Random) -> tuple[str, str]:
    n = rng.randint(10, 199)
    return f"WORKSTATION-{n:03d}", f"192.168.{rng.randint(1, 9)}.{n}"


def vary(key: str, base: dict, rng: random.Random, when: datetime, now: datetime) -> dict:
    inc = copy.deepcopy(base)
    inc["timestamp"] = iso(when)
    user = rng.choice(USERS)
    host, ip = workstation(rng)
    if key in ("known_benign_software", "suspicious_powershell", "malicious_domain", "prompt_injection"):
        inc["asset"].update(hostname=host, ip=ip)
        inc["user"]["username"] = user
        if "department" in inc["user"] or key == "suspicious_powershell":
            inc["user"]["department"] = rng.choice(DEPARTMENTS)
        for field in ("command_line", "path"):
            if inc.get("process", {}).get(field):
                inc["process"][field] = inc["process"][field].replace(base["user"]["username"], user)
        if inc.get("file", {}).get("path"):
            inc["file"]["path"] = inc["file"]["path"].replace(base["user"]["username"], user)
    if key == "suspicious_powershell":
        inc["process"]["parent"] = rng.choice(["winword.exe", "excel.exe", "outlook.exe"])
    if key == "malicious_domain":
        inc["network"]["bytes_out"] = rng.randint(2_000, 400_000)
    if key == "known_benign_software":
        inc["asset"]["criticality"] = rng.choice(["low", "medium"])
    if key == "insufficient_evidence":
        inc["asset"]["hostname"] = host
        inc["indicators"] = [{"type": "domain", "value": rng.choice(RARE_DOMAINS)}]
        inc["severity"] = rng.choice(["low", "medium"])
    if key == "suspicious_authentication":
        inc["user"].update(username=user, department=rng.choice(DEPARTMENTS))
        auth = inc["authentication"]
        auth["failed_attempts"] = rng.choice([2, 4, 7, 15, 32, 47, 88, 140])
        auth["source_country"] = rng.choice(COUNTRIES + ["FR", "FR"])  # sometimes the usual country
        auth["mfa"] = rng.random() < 0.3
        auth["result"] = "success" if rng.random() < 0.7 else "failure"
        inc["alert"]["description"] = (f"{auth['failed_attempts']} failed sign-ins followed by a "
                                       f"{auth['result']} sign-in from {auth['source_country']}")
    if key == "legitimate_admin":
        # The change window in config/organization.yml is 2026-10-22 10:00-16:00 UTC. Stay inside it when it is
        # in the past; ~30 % of the time the script runs "outside the change" (other server), which the
        # decision engine must not treat as authorised.
        start = datetime(2026, 10, 22, 10, 0, tzinfo=timezone.utc)
        end = min(datetime(2026, 10, 22, 16, 0, tzinfo=timezone.utc), now)
        if end > start:
            inc["timestamp"] = iso(start + (end - start) * rng.random())
        if rng.random() < 0.3:
            inc["asset"]["hostname"] = rng.choice(["SRV-FILE-02", "SRV-APP-03"])
            inc["asset"]["ip"] = f"10.10.4.{rng.randint(30, 90)}"
    if key == "php_cgi_exploit":
        inc["asset"]["hostname"] = rng.choice(["WEB-PHP-01", "WEB-PHP-02", "WEB-INTRANET-01"])
    return inc


def post(api: str, key: str, payload: dict, cti_mode: str) -> dict:
    req = urllib.request.Request(f"{api}/api/v1/incidents?resubmit=true&cti_mode={cti_mode}",
                                 data=json.dumps(payload).encode(), method="POST",
                                 headers={"X-API-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def get(api: str, key: str, path: str) -> dict:
    req = urllib.request.Request(f"{api}/api/v1/{path}", headers={"X-API-Key": key})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--key", default="sfumato-dev-key-change-me", help="API key (see API_KEYS in .env)")
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--hours", type=float, default=24, help="spread alert timestamps over the last N hours")
    ap.add_argument("--cti-mode", choices=["demo", "live"], default="demo")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--wait", action="store_true", help="wait for every investigation and print a summary")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    templates = load_templates()
    keys = [k for k in WEIGHTS if k in templates]
    now = datetime.now(timezone.utc)
    batch = now.strftime("%m%d%H%M")
    submitted: list[tuple[str, str]] = []
    for n in range(1, args.count + 1):
        key = rng.choices(keys, weights=[WEIGHTS[k] for k in keys])[0]
        when = now - timedelta(hours=args.hours * rng.random())
        inc = vary(key, templates[key], rng, when, now)
        inc["incident_id"] = f"BKL-{batch}-{n:03d}"
        try:
            res = post(args.api, args.key, inc, args.cti_mode)
        except urllib.error.HTTPError as e:
            print(f"  ✗ {inc['incident_id']} ({key}): HTTP {e.code} {e.read()[:200]!r}")
            continue
        except urllib.error.URLError as e:
            print(f"Cannot reach the API at {args.api}: {e.reason}")
            return 1
        submitted.append((res["incident_id"], key))
        print(f"  ✓ {res['incident_id']:<22} {key:<26} {inc['timestamp']}")
    print(f"\n{len(submitted)} alert(s) queued for investigation (CTI mode: {args.cti_mode}).")

    if not args.wait or not submitted:
        return 0
    pending = {iid for iid, _ in submitted}
    t0 = time.time()
    while pending:
        time.sleep(3)
        for iid in list(pending):
            if get(args.api, args.key, f"incidents/{iid}")["status"] in ("completed", "needs_review", "failed"):
                pending.discard(iid)
        print(f"\r  investigated {len(submitted) - len(pending)}/{len(submitted)} "
              f"({int(time.time() - t0)} s)", end="", flush=True)
    print("\n")
    summary: dict[str, dict[str, int]] = {}
    for iid, key in submitted:
        inc = get(args.api, args.key, f"incidents/{iid}")
        verdict = inc["verdict"] or inc["status"].upper()
        summary.setdefault(key, {}).setdefault(verdict, 0)
        summary[key][verdict] += 1
    for key, verdicts in sorted(summary.items()):
        print(f"  {key:<26} " + ", ".join(f"{v}: {n}" for v, n in sorted(verdicts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
