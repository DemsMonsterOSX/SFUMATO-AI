"""Fetch free vulnerability feeds and publish them to the project's bucket.

Sources (all free, no account needed; an NVD key is optional and only raises the rate limit):
  * CISA Known Exploited Vulnerabilities (KEV): https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  * NIST NVD CVE API 2.0:                        https://nvd.nist.gov/developers/vulnerabilities
  * FIRST EPSS API (exploit probability):        https://www.first.org/epss/api

  python bigdata/cve_ingest.py --bucket sfumato-soc-4ab8ab-artifacts --days 30
  python bigdata/cve_ingest.py --dry-run --days 3          # fetch and summarise, write nothing outside --local-dir

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


def fetch_nvd(start: datetime, end: datetime, key: str | None) -> list[dict]:
    out, idx, total, pause = [], 0, None, (0.8 if key else 6.5)
    while total is None or idx < total:
        q = {"pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"), "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--local-dir", default=str(ROOT / "ml" / "cve"))
    ap.add_argument("--dry-run", action="store_true", help="do not upload to the bucket")
    a = ap.parse_args()
    if not a.dry_run and not a.bucket:
        sys.exit("--bucket is required unless --dry-run")
    key = os.environ.get("NVD_API_KEY") or None
    end = datetime.now(timezone.utc)
    print(f"KEV ...", flush=True)
    kev_raw = get(KEV_URL)
    kev = json.loads(kev_raw)
    kev_ids = {v["cveID"] for v in kev["vulnerabilities"]}
    print(f"  {len(kev_ids)} entries; NVD window {a.days} days ({'with' if key else 'without'} API key)", flush=True)
    raw: list[dict] = []
    step = timedelta(days=100)   # the NVD accepts windows up to 120 days
    s = end - timedelta(days=a.days)
    while s < end:
        e = min(s + step, end)
        raw += fetch_nvd(s, e, key)
        s = e
    cves = [compact(v, kev_ids) for v in raw]
    want = sorted({c["id"] for c in cves if (c["cvss"] or {}).get("score", 0) >= 7.0} | {v["cveID"] for v in kev["vulnerabilities"] if v["dateAdded"] >= (end - timedelta(days=a.days)).strftime("%Y-%m-%d")})
    print(f"EPSS for {len(want)} CVEs ...", flush=True)
    epss = fetch_epss(want)
    summary = summarise(kev, cves, epss, a.days)

    out = Path(tempfile.mkdtemp(prefix="sfumato-cve-"))
    (out / "kev.json").write_bytes(kev_raw)
    with gzip.open(out / "nvd_recent.jsonl.gz", "wt", encoding="utf-8") as fh:
        for c in cves:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    manifest = {"generated_at": summary["generated_at"], "files": {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(out.iterdir())},
                "counts": {"kev": len(kev_ids), "nvd_window": len(cves), "epss": len(epss)}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    Path(a.local_dir).mkdir(parents=True, exist_ok=True)
    shutil.copy(out / "summary.json", Path(a.local_dir) / "summary.json")
    print(f"summary: KEV {summary['kev']['total']} (+{summary['kev']['added_in_window']} in {a.days} d), NVD {len(cves)}, "
          f"severity {summary['nvd']['by_severity']}, EPSS {len(epss)}")
    if a.dry_run:
        print("dry run: nothing uploaded; files in", out)
        return
    g = gcloud()
    day = end.strftime("%Y-%m-%d")
    for dest in (f"gs://{a.bucket}/cve/{day}/", f"gs://{a.bucket}/cve/latest/"):
        subprocess.run([g, "storage", "cp", *map(str, sorted(out.iterdir())), dest, "--quiet"], check=True)
        print("uploaded to", dest)


if __name__ == "__main__":
    main()
