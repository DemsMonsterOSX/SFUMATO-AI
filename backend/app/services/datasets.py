"""Read-only browsing of the project's datasets in the bucket (list, preview of the first rows).

Strictly limited to an allow-list of prefixes: nothing else in the bucket (deployment packages, models, secrets-adjacent files)
can be listed or read through this API. Reads use the VM's own identity (metadata server token) with a byte Range, so even the
4 GB CSV files are previewed by reading only their first 256 KB. Elsewhere (local development) the service reports "unavailable".
"""
from __future__ import annotations

import csv
import io
import json
import posixpath
import re
import urllib.parse

import httpx

from app.core.config import get_settings

ALLOWED = {
    "bigdata/raw/": "CIC-IDS2018 raw CSV files (6.9 GB, 10 days of labelled network flows)",
    "stream/sample/": "stratified sample exported from BigQuery (Parquet)",
    "stream/replay/": "flows replayed in the streaming scenarios (Parquet)",
    "cve/latest/": "latest CVE feed (KEV, NVD window, summary, change events)",
    "procedures/": "response procedures (Markdown) and their index",
}
TEXT_EXT = {".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".md": "text", ".txt": "text"}
MAX_PREVIEW_BYTES = 256 * 1024
_MD = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"


def _bucket() -> str | None:
    m = re.match(r"^gs://([^/]+)", get_settings().ml_artifact_uri or "")
    return m.group(1) if m else None


def _token(c: httpx.Client) -> str | None:
    try:
        r = c.get(_MD, headers={"Metadata-Flavor": "Google"}, timeout=3.0)
        return r.json()["access_token"] if r.status_code == 200 else None
    except Exception:
        return None


def _safe(path: str, is_prefix: bool = False) -> str:
    p = posixpath.normpath(path.strip().lstrip("/")) if path.strip() else ""
    if is_prefix and path.endswith("/") and p:
        p += "/"
    if ".." in p.split("/") or "\\" in path or "\x00" in path:
        raise ValueError("invalid path")
    if not any((p if p.endswith("/") or not is_prefix else p + "/").startswith(a) for a in ALLOWED):
        raise PermissionError("this location is not exposed")
    return p


def roots() -> list[dict]:
    return [{"prefix": k, "description": v} for k, v in ALLOWED.items()]


def listing(prefix: str) -> dict:
    p = _safe(prefix, is_prefix=True)
    b = _bucket()
    if not b:
        return {"available": False, "items": [], "prefixes": []}
    with httpx.Client(timeout=8.0) as c:
        t = _token(c)
        if not t:
            return {"available": False, "items": [], "prefixes": []}
        params = {"prefix": p, "delimiter": "/", "maxResults": 200}
        r = c.get(f"https://storage.googleapis.com/storage/v1/b/{b}/o", params=params, headers={"Authorization": "Bearer " + t})
    if r.status_code != 200:
        return {"available": False, "items": [], "prefixes": []}
    j = r.json()
    items = [{"name": i["name"], "size": int(i["size"]), "updated": i.get("updated"),
              "kind": TEXT_EXT.get(posixpath.splitext(i["name"])[1].lower(), "binary")} for i in j.get("items", []) if not i["name"].endswith("/")]
    return {"available": True, "prefix": p, "items": items, "prefixes": j.get("prefixes", [])}


def preview(path: str, rows: int = 20) -> dict:
    p = _safe(path)
    ext = posixpath.splitext(p)[1].lower()
    kind = TEXT_EXT.get(ext)
    b = _bucket()
    if not b:
        return {"available": False}
    with httpx.Client(timeout=15.0) as c:
        t = _token(c)
        if not t:
            return {"available": False}
        h = {"Authorization": "Bearer " + t}
        meta = c.get(f"https://storage.googleapis.com/storage/v1/b/{b}/o/{urllib.parse.quote(p, safe='')}", headers=h)
        if meta.status_code != 200:
            return {"available": True, "error": "object not found"}
        size = int(meta.json()["size"])
        if kind is None:
            return {"available": True, "path": p, "size": size, "kind": "binary",
                    "note": "binary file (Parquet or compressed): query it with BigQuery or Spark instead of previewing it here"}
        r = c.get(f"https://storage.googleapis.com/storage/v1/b/{b}/o/{urllib.parse.quote(p, safe='')}?alt=media",
                  headers={**h, "Range": f"bytes=0-{MAX_PREVIEW_BYTES - 1}"})
    if r.status_code not in (200, 206):
        return {"available": True, "error": f"read failed (HTTP {r.status_code})"}
    text = r.content.decode("utf-8", errors="replace")
    truncated = size > len(r.content)
    out = {"available": True, "path": p, "size": size, "kind": kind, "truncated": truncated, "bytes_read": len(r.content)}
    if kind == "csv":
        lines = text.splitlines()
        if truncated and lines:
            lines = lines[:-1]   # the last line is cut by the byte limit
        parsed = list(csv.reader(io.StringIO("\n".join(lines))))
        out["columns"] = parsed[0] if parsed else []
        out["rows"] = parsed[1:rows + 1]
        out["column_count"] = len(out["columns"])
    elif kind == "jsonl":
        out["rows"] = [json.loads(x) for x in text.splitlines()[:rows] if x.strip().startswith("{")]
    else:
        out["text"] = text[:6000]
    return out
