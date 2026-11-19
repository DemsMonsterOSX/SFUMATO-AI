"""Search over the project's own documentation (README and docs/*.md) so the agent can explain how the platform works.

Chunks follow the Markdown headings (at most about 1,200 characters). Lexical BM25 with the same tokenizer as the procedures.
Reference text about the project, never evidence about an incident.
"""
from __future__ import annotations

import math
import re
import threading
from collections import Counter
from pathlib import Path

from app.core.config import get_settings
from app.services.procedures import tokens

_lock = threading.Lock()
_cache: dict = {"sig": None, "chunks": [], "tf": [], "len": [], "df": Counter(), "avg": 1.0}


def _files() -> list[Path]:
    root = Path(get_settings().repo_dir)
    out = [root / "README.md"] if (root / "README.md").exists() else []
    d = root / "docs"
    return out + (sorted(d.glob("*.md")) if d.exists() else [])


def _chunks(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    name = f"{path.parent.name}/{path.name}" if path.parent.name == "docs" else path.name
    parts, head, buf = [], path.stem, []
    def flush():
        body = "\n".join(buf).strip()
        while body:
            parts.append({"file": name, "section": head, "text": body[:1200]})
            body = body[1200:].strip()
    for line in text.splitlines():
        if re.match(r"^#{1,3} ", line):
            flush()
            buf = []
            head = line.lstrip("# ").strip()
        else:
            buf.append(line)
    flush()
    return [c for c in parts if len(c["text"]) > 60]


def _load() -> None:
    files = _files()
    sig = tuple((str(f), f.stat().st_mtime) for f in files)
    with _lock:
        if _cache["sig"] == sig:
            return
        chunks = [c for f in files for c in _chunks(f)]
        tf = [Counter(tokens(c["file"] + " " + c["section"] + " " + c["section"] + " " + c["text"])) for c in chunks]
        df: Counter = Counter()
        for c in tf:
            df.update(c.keys())
        _cache.update(sig=sig, chunks=chunks, tf=tf, len=[sum(c.values()) for c in tf], df=df, avg=sum(sum(c.values()) for c in tf) / max(len(tf), 1))


def search(query: str, limit: int = 3) -> list[dict]:
    _load()
    q = set(tokens(query))
    n = len(_cache["chunks"])
    scored = []
    for i, c in enumerate(_cache["chunks"]):
        s = 0.0
        for t in q:
            f = _cache["tf"][i].get(t, 0)
            if f:
                idf = math.log(1 + (n - _cache["df"][t] + 0.5) / (_cache["df"][t] + 0.5))
                s += idf * f * 2.5 / (f + 1.5 * (0.25 + 0.75 * _cache["len"][i] / _cache["avg"]))
        if s > 0:
            scored.append((s, c))
    scored.sort(key=lambda x: -x[0])
    return [{**c, "score": round(s, 2)} for s, c in scored[:limit]]
