"""Phase 1 - Acquisition: copy the CSE-CIC-IDS2018 "Processed Traffic Data for ML Algorithms" CSVs (6.9 GB, public AWS Open Data
bucket, no account needed) straight into your GCS bucket. Streams every file (nothing is written to local disk).

  python bigdata/ingest.py --bucket sfumato-soc-4ab8ab-artifacts [--prefix bigdata/raw] [--dry-run]

Needs: gcloud authenticated, write access to the bucket (your own account is enough). Idempotent: skips files already
present with the same size. Licence/credit: Canadian Institute for Cybersecurity (UNB) + CSE, see docs/BIGDATA_PROJECT.md.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request

HOST = "https://cse-cic-ids2018.s3.amazonaws.com"
SRC_PREFIX = "Processed Traffic Data for ML Algorithms/"


def list_source() -> list[tuple[str, int]]:
    url = f"{HOST}/?prefix={urllib.parse.quote(SRC_PREFIX)}&delimiter=/"
    xml = urllib.request.urlopen(url, timeout=60).read().decode()
    out = [(k, int(s)) for k, s in re.findall(r"<Key>([^<]*)</Key>.*?<Size>(\d+)</Size>", xml, re.S) if k.endswith(".csv")]
    if not out:
        raise SystemExit("no CSV listed: the source bucket layout changed")
    return out


def gcloud() -> str:
    exe = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    if not exe:
        raise SystemExit("gcloud not found in PATH")
    return exe


def remote_size(g: str, uri: str) -> int | None:
    r = subprocess.run([g, "storage", "ls", "-l", uri], capture_output=True, text=True)
    m = re.match(r"\s*(\d+)\s", r.stdout) if r.returncode == 0 else None
    return int(m.group(1)) if m else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--prefix", default="bigdata/raw")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    files = list_source()
    total = sum(s for _, s in files)
    print(f"{len(files)} files, {total / 1e9:.2f} GB -> gs://{a.bucket}/{a.prefix}/")
    if a.dry_run:
        for k, s in files:
            print(f"  {s / 1e6:9.1f} MB  {k.removeprefix(SRC_PREFIX)}")
        return
    g = gcloud()
    for k, size in files:
        name = k.removeprefix(SRC_PREFIX)
        dest = f"gs://{a.bucket}/{a.prefix}/{name}"
        if remote_size(g, dest) == size:
            print(f"skip   {name} (already there)")
            continue
        print(f"copy   {name} ({size / 1e6:.0f} MB) ...", flush=True)
        src = urllib.request.urlopen(f"{HOST}/{urllib.parse.quote(k)}", timeout=120)
        p = subprocess.Popen([g, "storage", "cp", "-", dest, "--quiet"], stdin=subprocess.PIPE)
        copied = 0
        try:
            while chunk := src.read(8 * 1024 * 1024):
                p.stdin.write(chunk)
                copied += len(chunk)
            p.stdin.close()
        except BrokenPipeError:
            pass
        if p.wait() != 0 or copied != size:
            sys.exit(f"FAILED on {name} ({copied}/{size} bytes)")
    print("done")


if __name__ == "__main__":
    main()
