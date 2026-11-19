"""Fetch free vulnerability feeds and publish them to the project's bucket.

Sources (all free, no account needed; an NVD key is optional and only raises the rate limit):
  * CISA Known Exploited Vulnerabilities (KEV): https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  * NIST NVD CVE API 2.0:                        https://nvd.nist.gov/developers/vulnerabilities
  * FIRST EPSS API (exploit probability):        https://www.first.org/epss/api

  python bigdata/cve_ingest.py --bucket sfumato-soc-4ab8ab-artifacts --days 30
  python bigdata/cve_ingest.py --dry-run --days 3          # fetch and summarise, write nothing outside --local-dir

Modes: full (default, rebuilds the whole window) and --incremental (hourly job: loads cve/latest, asks the NVD only for CVEs
modified since the previous run, merges them, refreshes EPSS once per day). In a container (Cloud Run job) uploads use the
google-cloud-storage client with the job's service account; on a workstation they use `gcloud storage cp`.

Outputs: gs://BUCKET/cve/<YYYY-MM-DD>/ and gs://BUCKET/cve/latest/ with kev.json, nvd_recent.jsonl.gz, summary.json, manifest.json;
a copy of summary.json in ml/cve/ (shipped with the web app as a fallback). Idempotent: re-running overwrites `latest`.
Limits: the NVD often has no CVSS score for a CVE during its first days (status "Awaiting Analysis"); EPSS is fetched only for
KEV entries and for CVEs scored >= 7.0, not for every CVE.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
UA = "sfumato-cve-ingest/1.0 (course project)"


def get(url: str, timeout: int = 90, retries: int = 5, headers: dict | None = None) -> bytes:
    wait = 8.0
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 502, 503, 504) and i < retries - 1:
                time.sleep(wait)
                wait *= 2
                continue
            raise
        except (urllib.error.URLError, TimeoutError):
            if i == retries - 1:
                raise
            time.sleep(wait)
            wait *= 2
    raise RuntimeError("unreachable")


def best_cvss(metrics: dict) -> dict | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            d = m.get("cvssData", {})
            if "baseScore" in d:
                return {"version": d.get("version"), "score": d["baseScore"],
                        "severity": (d.get("baseSeverity") or m.get("baseSeverity") or "").upper() or None, "vector": d.get("vectorString")}
    return None


def compact(v: dict, kev_ids: set[str]) -> dict:
    c = v["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = sorted({x["value"] for w in c.get("weaknesses", []) for x in w.get("description", []) if x.get("value", "").startswith("CWE-")})
    return {"id": c["id"], "published": c.get("published"), "modified": c.get("lastModified"), "status": c.get("vulnStatus"),
            "description": desc[:400], "cvss": best_cvss(c.get("metrics", {})), "cwe": cwes, "kev": c["id"] in kev_ids}


def fetch_nvd(start: datetime, end: datetime, key: str | None, kind: str = "pub") -> list[dict]:
    """kind = "pub" (published in the window) or "mod" (last modified in the window: new and updated CVEs)."""
    out, idx, total, pause = [], 0, None, (0.8 if key else 6.5)
    names = ("pubStartDate", "pubEndDate") if kind == "pub" else ("lastModStartDate", "lastModEndDate")
    while total is None or idx < total:
        q = {names[0]: start.strftime("%Y-%m-%dT%H:%M:%S.000"), names[1]: end.strftime("%Y-%m-%dT%H:%M:%S.000"),
             "resultsPerPage": 2000, "startIndex": idx}
        data = json.loads(get(f"{NVD_URL}?{urllib.parse.urlencode(q)}", headers={"apiKey": key} if key else None))
        total = data["totalResults"]
        out += data["vulnerabilities"]
        idx += data["resultsPerPage"] if data["resultsPerPage"] else 2000
        print(f"  NVD {min(idx, total)}/{total}", flush=True)
        if idx < total:
            time.sleep(pause)
    return out


def fetch_epss(ids: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for i in range(0, len(ids), 80):
        chunk = ids[i:i + 80]
        url = f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(chunk), 'limit': 100})}"
        try:
            for r in json.loads(get(url)).get("data", []):
                out[r["cve"]] = {"epss": float(r["epss"]), "percentile": float(r["percentile"])}
        except Exception as e:  # EPSS is an enrichment: never fail the whole run for it
            print(f"  EPSS chunk {i // 80} failed: {type(e).__name__}", file=sys.stderr)
        time.sleep(0.4)
    return out


def summarise(kev: dict, cves: list[dict], epss: dict, days: int) -> dict:
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    vulns = kev["vulnerabilities"]
    kev_recent = sorted([v for v in vulns if v["dateAdded"] >= cutoff], key=lambda v: v["dateAdded"], reverse=True)
    sev = Counter((c["cvss"] or {}).get("severity") or "UNSCORED" for c in cves)
    per_day: dict[str, Counter] = {}
    for c in cves:
        per_day.setdefault((c["published"] or "")[:10], Counter())[(c["cvss"] or {}).get("severity") or "UNSCORED"] += 1
    top_cvss = sorted([c for c in cves if c["cvss"]], key=lambda c: (-c["cvss"]["score"], c["id"]))[:40]
    for c in top_cvss + cves:
        if c["id"] in epss:
            c["epss"] = epss[c["id"]]
    top_epss = sorted([c for c in cves if "epss" in c], key=lambda c: -c["epss"]["epss"])[:30]
    kev_view = [{"id": v["cveID"], "vendor": v["vendorProject"], "product": v["product"], "name": v["vulnerabilityName"], "added": v["dateAdded"],
                 "due": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse"), "description": v["shortDescription"][:300],
                 "epss": epss.get(v["cveID"])} for v in kev_recent[:60]]
    return {
        "generated_at": now.isoformat(), "window_days": days,
        "kev": {"catalog_version": kev.get("catalogVersion"), "released": kev.get("dateReleased"), "total": len(vulns),
                "added_in_window": len(kev_recent), "ransomware_known": sum(1 for v in vulns if v.get("knownRansomwareCampaignUse") == "Known"),
                "recent": kev_view},
        "nvd": {"published_in_window": len(cves), "by_severity": dict(sev), "scored_share": round(sum(1 for c in cves if c["cvss"]) / max(len(cves), 1), 3),
                "in_kev": sum(1 for c in cves if c["kev"]),
                "per_day": [{"day": d, **dict(c)} for d, c in sorted(per_day.items())], "top_cvss": top_cvss},
        "epss": {"top": top_epss, "fetched_for": len(epss)},
        "sources": ["CISA KEV", "NIST NVD API 2.0", "FIRST EPSS API"],
        "limitations": ["Many recent CVEs have no CVSS score yet (awaiting analysis): severity counts are incomplete.",
                        "EPSS was fetched only for KEV entries and CVEs scored 7.0 or higher.",
                        "Only CVEs published in the window are listed; older CVEs are not in nvd_recent."],
    }


def gcloud() -> str:
    exe = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    if not exe:
        sys.exit("gcloud not found in PATH")
    return exe


def _client():
    try:
        from google.cloud import storage  # type: ignore
        return storage.Client()
    except Exception:
        return None


def gcs_read(bucket: str, name: str) -> bytes | None:
    c = _client()
    if c is not None:
        b = c.bucket(bucket).blob(name)
        return b.download_as_bytes() if b.exists() else None
    out = Path(tempfile.mkdtemp()) / "x"
    r = subprocess.run([gcloud(), "storage", "cp", f"gs://{bucket}/{name}", str(out), "--quiet"], capture_output=True)
    return out.read_bytes() if r.returncode == 0 and out.exists() else None


def gcs_write_all(bucket: str, files: dict[str, bytes], prefixes: list[str]) -> None:
    c = _client()
    for pre in prefixes:
        for name, data in files.items():
            if c is not None:
                c.bucket(bucket).blob(f"{pre}{name}").upload_from_string(data)
            else:
                tmp = Path(tempfile.mkdtemp()) / name
                tmp.write_bytes(data)
                subprocess.run([gcloud(), "storage", "cp", str(tmp), f"gs://{bucket}/{pre}{name}", "--quiet"], check=True)
        print("uploaded to", f"gs://{bucket}/{pre}")


def load_previous(bucket: str) -> tuple[list[dict], dict | None]:
    raw = gcs_read(bucket, "cve/latest/nvd_recent.jsonl.gz")
    man = gcs_read(bucket, "cve/latest/summary.json")
    if not raw or not man:
        return [], None
    recs = [json.loads(line) for line in gzip.decompress(raw).decode("utf-8").splitlines() if line.strip()]
    return recs, json.loads(man)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", default=os.environ.get("BUCKET"))
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--incremental", action="store_true", help="merge the CVEs modified since the previous run into cve/latest")
    ap.add_argument("--local-dir", default=str(ROOT / "ml" / "cve"))
    ap.add_argument("--dry-run", action="store_true", help="do not upload to the bucket")
    a = ap.parse_args()
    if (not a.dry_run or a.incremental) and not a.bucket:
        sys.exit("--bucket (or the BUCKET variable) is required unless --dry-run without --incremental")
    key = os.environ.get("NVD_API_KEY") or None
    end = datetime.now(timezone.utc)
    today = end.strftime("%Y-%m-%d")
    print("KEV ...", flush=True)
    kev_raw = get(KEV_URL)
    kev = json.loads(kev_raw)
    kev_ids = {v["cveID"] for v in kev["vulnerabilities"]}
    window_start = end - timedelta(days=a.days)
    events: list[dict] = []

    prev, prev_summary = (load_previous(a.bucket) if a.incremental else ([], None))
    since = None
    if prev_summary:
        since = datetime.fromisoformat(prev_summary["generated_at"]) - timedelta(minutes=15)
        if end - since > timedelta(days=100):
            since = None
    if a.incremental and since:
        print(f"incremental: {len(prev)} CVEs held, NVD modified since {since:%Y-%m-%d %H:%M}Z", flush=True)
        changed = [compact(v, kev_ids) for v in fetch_nvd(since, end, key, "mod")]
        merged = {c["id"]: c for c in prev}
        for c in changed:
            old = merged.get(c["id"])
            if old and old.get("epss"):
                c["epss"], c["epss_at"] = old["epss"], old.get("epss_at")
            events.append({"type": "updated" if old else "new", "id": c["id"], "severity": (c["cvss"] or {}).get("severity"), "kev": c["kev"],
                           "published": c["published"], "at": end.isoformat()})
            merged[c["id"]] = c
        for c in merged.values():   # the KEV flag can change without any NVD change
            if c["id"] in kev_ids and not c["kev"]:
                c["kev"] = True
                events.append({"type": "kev_added", "id": c["id"], "at": end.isoformat()})
        cves = [c for c in merged.values() if (c["published"] or "")[:10] >= window_start.strftime("%Y-%m-%d")]
    else:
        print(f"full window {a.days} days ({'with' if key else 'without'} API key)", flush=True)
        raw: list[dict] = []
        s = window_start
        while s < end:
            e = min(s + timedelta(days=100), end)   # the NVD accepts windows up to 120 days
            raw += fetch_nvd(s, e, key)
            s = e
        cves = [compact(v, kev_ids) for v in raw]
        old_epss = {c["id"]: c for c in prev if c.get("epss")}
        for c in cves:
            if c["id"] in old_epss:
                c["epss"], c["epss_at"] = old_epss[c["id"]]["epss"], old_epss[c["id"]].get("epss_at")

    recent_kev = {v["cveID"] for v in kev["vulnerabilities"] if v["dateAdded"] >= window_start.strftime("%Y-%m-%d")}
    want = sorted(c["id"] for c in cves if ((c["cvss"] or {}).get("score", 0) >= 7.0 or c["id"] in recent_kev) and c.get("epss_at") != today)
    extra_kev = sorted(recent_kev - {c["id"] for c in cves})   # recent KEV entries published before the window
    print(f"EPSS for {len(want) + len(extra_kev)} CVEs (refreshed once per day) ...", flush=True)
    got = fetch_epss(want + extra_kev)
    for c in cves:
        if c["id"] in got:
            c["epss"], c["epss_at"] = got[c["id"]], today
    epss = {c["id"]: c["epss"] for c in cves if c.get("epss")} | {k: v for k, v in got.items() if k in extra_kev}
    summary = summarise(kev, cves, epss, a.days)
    summary["mode"] = "incremental" if (a.incremental and since) else "full"
    summary["last_run_changes"] = len(events)

    files: dict[str, bytes] = {"kev.json": kev_raw}
    files["nvd_recent.jsonl.gz"] = gzip.compress("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cves).encode("utf-8"))
    files["summary.json"] = json.dumps(summary, ensure_ascii=False, indent=1).encode("utf-8")
    files["events.jsonl"] = "".join(json.dumps(e) + "\n" for e in events).encode("utf-8")
    files["manifest.json"] = json.dumps({"generated_at": summary["generated_at"], "mode": summary["mode"],
                                         "files": {n: hashlib.sha256(d).hexdigest() for n, d in sorted(files.items())},
                                         "counts": {"kev": len(kev_ids), "nvd_window": len(cves), "epss": len(epss), "events": len(events)}}, indent=1).encode("utf-8")
    if not os.environ.get("CLOUD_RUN_JOB") and a.local_dir:
        Path(a.local_dir).mkdir(parents=True, exist_ok=True)
        (Path(a.local_dir) / "summary.json").write_bytes(files["summary.json"])
    print(f"[{summary['mode']}] KEV {summary['kev']['total']} (+{summary['kev']['added_in_window']} in {a.days} d), NVD {len(cves)}, "
          f"changes this run {len(events)}, severity {summary['nvd']['by_severity']}, EPSS {len(epss)}")
    if a.dry_run:
        print("dry run: nothing uploaded")
        return
    gcs_write_all(a.bucket, files, [f"cve/{today}/", "cve/latest/"])


if __name__ == "__main__":
    main()
