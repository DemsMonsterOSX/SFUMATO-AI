#!/usr/bin/env python3
"""Build the Sfumato knowledge base (RAG) from the Hugging Face dataset Vyber07/cyber-security.

Designed to run on a free Kaggle notebook (see sfumato_kb_kaggle.ipynb) or locally:

    pip install "fastembed==0.9.1" "huggingface_hub==1.33.0" numpy
    export HF_TOKEN=hf_...            # the dataset is gated: accept its terms on huggingface.co first
    python build_kb.py --out kb_out --push-to <your-user>/sfumato-kb

Pipeline
--------
1. List the dataset files; keep JSON/JSONL text only (no source-code tarballs, scripts or notes) and
   de-duplicate files by content hash (the dataset stores many files twice).
2. Stream records and normalise the known formats (ShareGPT conversations, Instruction/Input/Output,
   generic question/answer objects) into (title, body, metadata).
3. Keep *defensive* content only: records must carry detection / response / hardening signals.
   Purely offensive material is dropped, because the knowledge base feeds a defensive SOC assistant.
4. De-duplicate records, split them into overlapping chunks, embed the chunks with
   BAAI/bge-small-en-v1.5 (fastembed, ONNX — the backend embeds queries with the very same model).
5. Write manifest.json + chunks.jsonl.gz + embeddings.npy (float16, L2-normalised) and optionally
   push them to a private Hugging Face dataset repository that Sfumato downloads at start-up.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator

import numpy as np

BUILDER_VERSION = "1.0"
DEFAULT_DATASET = "Vyber07/cyber-security"
DEFAULT_MODEL = "BAAI/bge-small-en-v1.5"

DEFENSIVE = re.compile(
    r"\b(detect\w*|sigma|yara|kql|splunk|siem|edr|xdr|mitigat\w*|remediat\w*|harden\w*|patch\w*|"
    r"incident response|forensic\w*|triage|ioc|indicators? of compromise|monitor\w*|alert\w*|containment|"
    r"contain\w*|eradicat\w*|defen[cs]\w*|logging|audit\w*|suricata|snort|zeek|sysmon|event id|"
    r"threat hunt\w*|blue team|soc\b|baseline|least privilege|countermeasure\w*)\b", re.IGNORECASE)
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
TITLE_KEYS = ("instruction", "question", "prompt", "query", "title", "task", "input", "topic", "name")
BODY_KEYS = ("output", "answer", "response", "completion", "content", "text", "body", "description",
             "explanation", "solution", "detection", "mitigation", "remediation")
LIST_KEYS = ("data", "records", "examples", "items", "entries", "rows", "samples")


# ------------------------------------------------------------------------------------------- normalisation
def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (list, tuple)):
        return "\n".join(_s(x) for x in v if _s(x))
    if isinstance(v, dict):
        return "\n".join(f"{k}: {_s(x)}" for k, x in v.items() if _s(x))
    return str(v)


def iter_records(obj) -> Iterator[dict]:
    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                yield x
    elif isinstance(obj, dict):
        for k in LIST_KEYS:
            if isinstance(obj.get(k), list):
                yield from iter_records(obj[k])
                return
        yield obj


def normalize(rec: dict) -> tuple[str, str, dict] | None:
    low = {str(k).lower(): v for k, v in rec.items()}
    meta_raw = low.get("metadata") or low.get("meta") or {}
    meta = meta_raw if isinstance(meta_raw, dict) else {}
    title = body = ""
    conv = low.get("conversations") or low.get("messages")
    if isinstance(conv, list) and conv:
        asks, answers = [], []
        for m in conv:
            if not isinstance(m, dict):
                continue
            role = str(m.get("from") or m.get("role") or "").lower()
            text = _s(m.get("value") or m.get("content"))
            if role in ("human", "user"):
                asks.append(text)
            elif role in ("gpt", "assistant", "model", "bot"):
                answers.append(text)
        title, body = (asks[0] if asks else ""), "\n\n".join(answers)
    else:
        title = "\n".join(_s(low[k]) for k in TITLE_KEYS if _s(low.get(k)))[:600]
        body = "\n\n".join(_s(low[k]) for k in BODY_KEYS if _s(low.get(k)))
        if not body:  # unknown shape: keep the long string fields
            body = "\n\n".join(_s(v) for k, v in low.items() if k not in ("metadata", "meta") and len(_s(v)) > 80)
    body = body.strip()
    if len(body) < 200:
        return None
    md = {
        "domain": _s(meta.get("domain") or low.get("domain") or low.get("category"))[:80],
        "subdomain": _s(meta.get("subdomain"))[:80],
        "attack_types": meta.get("attack_types") or [],
        "defense_types": meta.get("defense_types") or [],
        "tools": meta.get("tools") or [],
        "source": _s(meta.get("source"))[:200],
    }
    return (title or body.split("\n", 1)[0])[:300], body, md


def is_defensive(title: str, body: str) -> tuple[bool, int]:
    hits = len(DEFENSIVE.findall(title + " " + body[:20000]))
    return hits >= 3, hits


def chunk(title: str, body: str, size: int, overlap: int, max_chunks: int) -> list[str]:
    paras = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
    chunks, cur = [], ""
    for p in paras:
        while len(p) > size:  # very long paragraph: hard split
            head, p = p[:size], p[size - overlap:]
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(head)
        if len(cur) + len(p) + 2 > size and cur:
            chunks.append(cur)
            cur = cur[-overlap:] + "\n\n" + p if overlap else p
        else:
            cur = f"{cur}\n\n{p}" if cur else p
    if cur:
        chunks.append(cur)
    return [f"{title}\n\n{c}" for c in chunks[:max_chunks]]


def _fingerprint(text: str) -> str:
    return hashlib.sha1(re.sub(r"\s+", " ", text.lower())[:4000].encode()).hexdigest()


# ------------------------------------------------------------------------------------------------ sources
class Source:
    """A list of files with a way to stream their bytes (local folder or Hugging Face dataset)."""

    def files(self) -> list[dict]:
        raise NotImplementedError

    def open(self, path: str):
        raise NotImplementedError


class LocalSource(Source):
    def __init__(self, root: str):
        self.root = Path(root)

    def files(self) -> list[dict]:
        out = []
        for p in sorted(self.root.rglob("*")):
            if p.is_file():
                data = p.read_bytes()
                out.append({"path": p.relative_to(self.root).as_posix(), "size": len(data),
                            "hash": hashlib.sha256(data).hexdigest()})
        return out

    def open(self, path: str):
        return open(self.root / path, "rb")

    def describe(self) -> dict:
        return {"type": "local", "path": str(self.root)}


class HubSource(Source):
    def __init__(self, repo: str, revision: str, token: str | None):
        from huggingface_hub import HfApi, HfFileSystem

        self.repo, self.token = repo, token
        self.api = HfApi(token=token)
        info = self.api.dataset_info(repo, revision=revision)
        self.revision = info.sha  # pin the exact commit for reproducibility
        self.fs = HfFileSystem(token=token)

    def files(self) -> list[dict]:
        out = []
        for f in self.api.list_repo_tree(self.repo, repo_type="dataset", revision=self.revision, recursive=True):
            if not hasattr(f, "size"):
                continue  # folder
            lfs = getattr(f, "lfs", None)
            sha = (lfs.get("sha256") if isinstance(lfs, dict) else getattr(lfs, "sha256", None)) or f.blob_id
            out.append({"path": f.path, "size": f.size or 0, "hash": sha})
        return out

    def open(self, path: str):
        return self.fs.open(f"datasets/{self.repo}@{self.revision}/{path}", "rb", block_size=8 * 1024 * 1024)

    def describe(self) -> dict:
        return {"type": "huggingface", "repo": self.repo, "revision": self.revision,
                "url": f"https://huggingface.co/datasets/{self.repo}"}


def select_files(files: list[dict], max_file_mb: float, max_json_mb: float) -> tuple[list[dict], Counter]:
    reasons: Counter = Counter()
    seen: set[str] = set()
    keep = []
    for f in sorted(files, key=lambda f: (f["path"].count("__"), "__dup" in f["path"], f["path"])):
        ext = f["path"].rsplit(".", 1)[-1].lower()
        if ext not in ("json", "jsonl"):
            reasons[f"skipped: .{ext} file"] += 1
            continue
        if "__dup" in f["path"] or f["hash"] in seen:
            reasons["skipped: duplicate file"] += 1
            continue
        mb = f["size"] / 1e6
        if mb > max_file_mb or (ext == "json" and mb > max_json_mb):
            reasons["skipped: too large (raise --max-file-mb / --max-json-mb)"] += 1
            continue
        seen.add(f["hash"])
        keep.append(f)
    return keep, reasons


def read_records(src: Source, path: str, max_records: int) -> Iterator[dict]:
    with src.open(path) as fh:
        if path.lower().endswith(".jsonl"):
            n = 0
            for line in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for r in iter_records(obj):
                    yield r
                    n += 1
                    if n >= max_records:
                        return
        else:
            try:
                obj = json.loads(fh.read().decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                return
            for n, r in enumerate(iter_records(obj)):
                if n >= max_records:
                    return
                yield r


# ---------------------------------------------------------------------------------------------- embedding
def fastembed_embedder(model: str, batch: int, gpu: bool) -> Callable[[list[str]], np.ndarray]:
    from fastembed import TextEmbedding

    kwargs = {"providers": ["CUDAExecutionProvider", "CPUExecutionProvider"]} if gpu else {}
    m = TextEmbedding(model, **kwargs)
    return lambda texts: np.asarray(list(m.passage_embed(texts, batch_size=batch)), dtype=np.float32)


def build(src: Source, out: Path, embed: Callable[[list[str]], np.ndarray], model_name: str, *,
          max_file_mb: float = 800, max_json_mb: float = 250, max_records_per_file: int = 50_000,
          max_chunks: int = 400_000, chunk_chars: int = 1200, overlap: int = 150, chunks_per_record: int = 6,
          log: Callable[[str], None] = print) -> dict:
    t0 = time.time()
    out.mkdir(parents=True, exist_ok=True)
    files, skipped = select_files(src.files(), max_file_mb, max_json_mb)
    log(f"{len(files)} file(s) selected; skipped: {dict(skipped)}")
    stats = Counter()
    per_file = []
    seen: set[str] = set()
    texts: list[str] = []
    rows: list[dict] = []
    for f in files:
        fs = Counter()
        try:
            for rec in read_records(src, f["path"], max_records_per_file):
                fs["records"] += 1
                norm = normalize(rec)
                if not norm:
                    fs["too_short_or_unknown"] += 1
                    continue
                title, body, md = norm
                ok, hits = is_defensive(title, body)
                if not ok:
                    fs["not_defensive"] += 1
                    continue
                fp = _fingerprint(body)
                if fp in seen:
                    fs["duplicate_record"] += 1
                    continue
                seen.add(fp)
                folder = f["path"].split("/")[0] if "/" in f["path"] else f["path"].split("__")[0]
                domain = md["domain"] or folder.rsplit(".", 1)[0]
                techniques = sorted(set(TECHNIQUE.findall(title + " " + body)))[:20]
                rid = fp[:16]
                for i, c in enumerate(chunk(title, body, chunk_chars, overlap, chunks_per_record)):
                    if len(texts) >= max_chunks:
                        break
                    texts.append(c)
                    rows.append({"record_id": rid, "chunk": i, "title": title, "text": c, "domain": domain,
                                 "techniques": techniques, "defensive_signals": hits, "source_file": f["path"],
                                 "attack_types": md["attack_types"][:10] if isinstance(md["attack_types"], list) else [],
                                 "defense_types": md["defense_types"][:10] if isinstance(md["defense_types"], list) else []})
                fs["kept"] += 1
        except Exception as e:  # one unreadable file must not stop the build
            fs["error"] += 1
            log(f"  ! {f['path']}: {type(e).__name__}: {e}")
        stats.update(fs)
        per_file.append({"path": f["path"], **fs})
        log(f"  {f['path']}: {dict(fs)}")
        if len(texts) >= max_chunks:
            log(f"Reached --max-chunks={max_chunks}; stopping")
            break
    if not texts:
        raise SystemExit("No defensive record found: nothing to embed (check access to the dataset / filters).")

    log(f"Embedding {len(texts)} chunk(s) with {model_name}…")
    vecs = []
    step = 4096
    for i in range(0, len(texts), step):
        vecs.append(embed(texts[i:i + step]))
        log(f"  {min(i + step, len(texts))}/{len(texts)}")
    emb = np.vstack(vecs).astype(np.float32)
    emb /= np.linalg.norm(emb, axis=1, keepdims=True) + 1e-12
    np.save(out / "embeddings.npy", emb.astype(np.float16))
    with gzip.open(out / "chunks.jsonl.gz", "wt", encoding="utf-8") as fh:
        for i, r in enumerate(rows):
            fh.write(json.dumps({"i": i, **r}, ensure_ascii=False) + "\n")
    manifest = {
        "name": "sfumato-knowledge-base", "format_version": 1, "builder_version": BUILDER_VERSION,
        "built_at": datetime.now(timezone.utc).isoformat(), "build_seconds": round(time.time() - t0, 1),
        "source": src.describe(), "source_license": "Apache-2.0 (as declared by the dataset)",
        "embedding_model": model_name, "dimensions": int(emb.shape[1]), "normalized": True, "dtype": "float16",
        "chunks": len(rows), "records": int(stats["kept"]),
        "filters": {"defensive_min_signals": 3, "chunk_chars": chunk_chars, "overlap": overlap,
                    "chunks_per_record": chunks_per_record, "max_records_per_file": max_records_per_file,
                    "max_file_mb": max_file_mb, "max_json_mb": max_json_mb},
        "stats": dict(stats), "skipped_files": dict(skipped), "files": per_file,
        "domains": dict(Counter(r["domain"] for r in rows).most_common(40)),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log(f"Done: {len(rows)} chunks from {stats['kept']} records in {manifest['build_seconds']} s → {out}")
    return manifest


def push(out: Path, repo_id: str, token: str | None, private: bool = True) -> str:
    from huggingface_hub import HfApi

    api = HfApi(token=token)
    api.create_repo(repo_id, repo_type="dataset", private=private, exist_ok=True)
    readme = out / "README.md"
    if not readme.exists():
        readme.write_text("---\nlicense: apache-2.0\n---\n# Sfumato knowledge base\n\nDerived from "
                          "[Vyber07/cyber-security](https://huggingface.co/datasets/Vyber07/cyber-security) "
                          "(defensive subset, chunked and embedded). See manifest.json.\n", encoding="utf-8")
    commit = api.upload_folder(folder_path=str(out), repo_id=repo_id, repo_type="dataset",
                               commit_message="Sfumato knowledge base build")
    return getattr(commit, "oid", None) or str(commit)


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    ap.add_argument("--revision", default="main")
    ap.add_argument("--local-dir", help="read files from a local folder instead of the Hub")
    ap.add_argument("--out", default="kb_out")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--gpu", action="store_true", help="use onnxruntime CUDA (pip install fastembed-gpu)")
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--max-file-mb", type=float, default=800)
    ap.add_argument("--max-json-mb", type=float, default=250)
    ap.add_argument("--max-records-per-file", type=int, default=50_000)
    ap.add_argument("--max-chunks", type=int, default=400_000)
    ap.add_argument("--push-to", help="private HF dataset repo to upload to, e.g. myuser/sfumato-kb")
    ap.add_argument("--publish-to", help="signed, versioned publication: gs://bucket/prefix | hf://user/repo | folder "
                                         "(needs ARTIFACT_SIGNING_KEY and artifacts.py next to this script)")
    args = ap.parse_args(list(argv) if argv is not None else None)

    token = os.environ.get("HF_TOKEN")
    src = LocalSource(args.local_dir) if args.local_dir else HubSource(args.dataset, args.revision, token)
    build(src, Path(args.out), fastembed_embedder(args.model, args.batch, args.gpu), args.model,
          max_file_mb=args.max_file_mb, max_json_mb=args.max_json_mb,
          max_records_per_file=args.max_records_per_file, max_chunks=args.max_chunks)
    if args.publish_to:
        import artifacts  # backend/app/storage/artifacts.py (the notebook writes it next to this file)

        key = os.environ.get("ARTIFACT_SIGNING_KEY")
        if not key:
            raise SystemExit("Set ARTIFACT_SIGNING_KEY (same value in Sfumato's .env)")
        store = artifacts.open_store(args.publish_to, token)
        version = artifacts.publish(store, "sfumato_kb", args.out, signing_key=key)
        print(f"Published sfumato_kb/{version} to {store.describe()}")
        print(f"In Sfumato's .env:  KB_ARTIFACT_URI={args.publish_to}")
    if args.push_to:
        rev = push(Path(args.out), args.push_to, token)
        print(f"Pushed to https://huggingface.co/datasets/{args.push_to} ({rev})")
        print(f"Set in Sfumato's .env:  KB_HF_REPO={args.push_to}   (and HF_TOKEN if the repo is private)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
