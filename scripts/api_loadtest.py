"""External load test of the dashboard API: requests per second by number of parallel connections.

  python scripts/api_loadtest.py --url https://<ip>.sslip.io --endpoint health --levels 1,2,4,8,16,32 --seconds 8
  python scripts/api_loadtest.py --url https://<ip>.sslip.io --endpoint "procedures?q=ransomware"

Credentials of the team login are read from secrets/gcp-team-credentials.txt (never printed). Path measured: this machine,
the Internet, Caddy (HTTPS and login), the Next.js proxy, the FastAPI API. It stops at the first level where more than 5 % of the
requests fail or are rate-limited (HTTP 429) and reports the best clean level. /health is never rate-limited; other routes are
subject to the API limiter (RATE_LIMIT_PER_MINUTE). The target is a 0.25-vCPU VM: keep the levels modest.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import ssl
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def worker(host: str, path: str, auth: str, end: float, out: list, lock: threading.Lock) -> None:
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, timeout=30, context=ctx)
    lat, err, lim = [], 0, 0
    while time.perf_counter() < end:
        t = time.perf_counter()
        try:
            conn.request("GET", path, headers={"Authorization": auth, "Cache-Control": "no-store"})
            r = conn.getresponse()
            r.read()
            if r.status == 429:
                lim += 1
            elif r.status >= 400:
                err += 1
        except Exception:
            err += 1
            conn.close()
            conn = http.client.HTTPSConnection(host, timeout=30, context=ctx)
        lat.append((time.perf_counter() - t) * 1000)
    conn.close()
    with lock:
        out.append((lat, err, lim))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--endpoint", default="health")
    ap.add_argument("--levels", default="1,2,4,8,16,32")
    ap.add_argument("--seconds", type=float, default=8)
    ap.add_argument("--json", help="write the results to this file")
    a = ap.parse_args()
    user, pw = (ROOT / "secrets" / "gcp-team-credentials.txt").read_text().split()[:2]
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    u = urllib.parse.urlparse(a.url)
    path = f"/api/backend/{a.endpoint}"
    print(f"{u.netloc}{path}  ({a.seconds:.0f} s per level)")
    print(f"{'conns':>6} {'requests':>9} {'req/s':>8} {'p50 ms':>8} {'p95 ms':>8} {'errors':>7} {'429':>6}")
    rows, best = [], 0
    for c in [int(x) for x in a.levels.split(",")]:
        out: list = []
        lock = threading.Lock()
        end = time.perf_counter() + a.seconds
        ths = [threading.Thread(target=worker, args=(u.netloc, path, auth, end, out, lock)) for _ in range(c)]
        t0 = time.perf_counter()
        [t.start() for t in ths]
        [t.join() for t in ths]
        dt = time.perf_counter() - t0
        lat = sorted(x for o in out for x in o[0])
        err, lim = sum(o[1] for o in out), sum(o[2] for o in out)
        n = max(1, len(lat))
        row = {"connections": c, "requests": len(lat), "rps": round(len(lat) / dt, 1), "p50_ms": round(lat[n // 2], 1) if lat else None,
               "p95_ms": round(lat[int(n * 0.95)], 1) if lat else None, "errors": err, "rate_limited": lim}
        rows.append(row)
        print(f"{c:>6} {row['requests']:>9} {row['rps']:>8} {row['p50_ms']:>8} {row['p95_ms']:>8} {err:>7} {lim:>6}", flush=True)
        if err / n > 0.05 or lim / n > 0.05:
            print("stopped: more than 5 % of the requests failed or were rate-limited")
            break
        best = max(best, row["rps"])
        time.sleep(2)
    print(f"best clean level: {best} requests/s")
    if a.json:
        Path(a.json).write_text(json.dumps({"endpoint": a.endpoint, "levels": rows, "best_clean_rps": best, "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S")}, indent=1))


if __name__ == "__main__":
    main()
