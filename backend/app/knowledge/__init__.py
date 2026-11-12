"""Knowledge base (RAG) for the AI investigator.

The knowledge base is built offline (ml/knowledge/build_kb.py, typically on a free Kaggle notebook) from
the Hugging Face dataset Vyber07/cyber-security and published to a private Hugging Face dataset repo.
At start-up the API downloads it once (KB_HF_REPO + HF_TOKEN) — or reads KB_LOCAL_PATH — and loads it:

* into PostgreSQL + pgvector (Docker deployment; shared with the worker process), or
* into memory (local development with SQLite, or when pgvector is unavailable).

Queries are embedded with the same model as the passages (fastembed / ONNX, CPU). Once downloaded,
everything works offline. Retrieved passages are general reference material, never evidence about the
incident: they cannot change the verdict.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import numpy as np
from sqlalchemy import text

from app.core.config import get_settings
from app.database.session import get_engine
from app.services.credentials import get_credentials

log = logging.getLogger("sfumato.knowledge")
ARTIFACT_FILES = ["manifest.json", "chunks.jsonl.gz", "embeddings.npy", "README.md"]
Embedder = Callable[[str], np.ndarray]


def _vec_literal(v: np.ndarray) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in v.tolist()) + "]"


class MemoryStore:
    name = "memory"

    def __init__(self, artifact: Path, manifest: dict):
        self.emb = np.load(artifact / "embeddings.npy").astype(np.float32)
        self.rows: list[dict] = []
        with gzip.open(artifact / "chunks.jsonl.gz", "rt", encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                r["text"] = r["text"][:2000]
                self.rows.append(r)
        if len(self.rows) != len(self.emb):
            raise ValueError(f"corrupted knowledge base: {len(self.rows)} chunks vs {len(self.emb)} vectors")

    def count(self) -> int:
        return len(self.rows)

    def search(self, q: np.ndarray, n: int) -> list[dict]:
        scores = self.emb @ q
        idx = np.argpartition(-scores, min(n, len(scores) - 1))[:n]
        idx = idx[np.argsort(-scores[idx])]
        return [{**self.rows[i], "score": float(scores[i])} for i in idx]


class PgVectorStore:
    """PostgreSQL + pgvector. A derived cache: the table is rebuilt whenever the artifact changes."""
    name = "pgvector"

    def __init__(self):
        self.engine = get_engine()

    @staticmethod
    def available() -> bool:
        eng = get_engine()
        if eng.dialect.name != "postgresql":
            return False
        try:
            with eng.begin() as c:
                c.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            return True
        except Exception as e:
            log.warning("pgvector unavailable (%s); falling back to the in-memory store", type(e).__name__)
            return False

    def loaded_version(self) -> dict | None:
        with self.engine.begin() as c:
            c.execute(text("CREATE TABLE IF NOT EXISTS kb_meta (key text PRIMARY KEY, value jsonb NOT NULL)"))
            row = c.execute(text("SELECT value FROM kb_meta WHERE key = 'loaded'")).first()
        return row[0] if row else None

    def load(self, artifact: Path, manifest: dict, version: str) -> None:
        cur = self.loaded_version()
        if cur and cur.get("version") == version:
            return
        dims = int(manifest["dimensions"])
        emb = np.load(artifact / "embeddings.npy").astype(np.float32)
        raw = self.engine.raw_connection()
        try:
            cur_ = raw.cursor()
            cur_.execute("DROP TABLE IF EXISTS kb_chunks")
            cur_.execute(f"""CREATE TABLE kb_chunks (i integer PRIMARY KEY, record_id text, title text, text text,
                             domain text, techniques jsonb, source_file text, embedding vector({dims}))""")
            with gzip.open(artifact / "chunks.jsonl.gz", "rt", encoding="utf-8") as fh, \
                    cur_.copy("COPY kb_chunks (i, record_id, title, text, domain, techniques, source_file, embedding) "
                              "FROM STDIN") as cp:
                for line in fh:
                    r = json.loads(line)
                    cp.write_row((r["i"], r["record_id"], r["title"], r["text"], r["domain"],
                                  json.dumps(r.get("techniques", [])), r["source_file"], _vec_literal(emb[r["i"]])))
            cur_.execute("CREATE INDEX kb_chunks_hnsw ON kb_chunks USING hnsw (embedding vector_cosine_ops)")
            cur_.execute("INSERT INTO kb_meta (key, value) VALUES ('loaded', %s) ON CONFLICT (key) DO UPDATE "
                         "SET value = EXCLUDED.value", (json.dumps({"version": version, "manifest": manifest}),))
            raw.commit()
        finally:
            raw.close()

    def count(self) -> int:
        with self.engine.connect() as c:
            return int(c.execute(text("SELECT count(*) FROM kb_chunks")).scalar() or 0)

    def search(self, q: np.ndarray, n: int) -> list[dict]:
        sql = text("SELECT i, record_id, title, text, domain, techniques, source_file, "
                   "1 - (embedding <=> CAST(:q AS vector)) AS score FROM kb_chunks "
                   "ORDER BY embedding <=> CAST(:q AS vector) LIMIT :n")
        with self.engine.connect() as c:
            rows = c.execute(sql, {"q": _vec_literal(q), "n": n}).mappings().all()
        return [dict(r) for r in rows]


class KnowledgeBase:
    def __init__(self, embedder_factory: Callable[[str], Embedder] | None = None):
        self._embedder_factory = embedder_factory
        self._embedder: Embedder | None = None
        self.store: MemoryStore | PgVectorStore | None = None
        self.manifest: dict | None = None
        self.state = "not_loaded"
        self.error: str | None = None
        self.source: str | None = None
        self.loaded_at: str | None = None
        self.latencies: list[float] = []
        self._lock = threading.Lock()
        self._last_attach = 0.0

    # ------------------------------------------------------------------ embedding
    def _embed_query(self, query: str) -> np.ndarray:
        if self._embedder is None:
            factory = self._embedder_factory or self._fastembed
            self._embedder = factory(self.manifest["embedding_model"] if self.manifest else get_settings().kb_embed_model)
        v = np.asarray(self._embedder(query), dtype=np.float32)
        return v / (np.linalg.norm(v) + 1e-12)

    @staticmethod
    def _fastembed(model: str) -> Embedder:
        from fastembed import TextEmbedding

        m = TextEmbedding(model, cache_dir=get_settings().kb_model_cache)
        return lambda q: np.asarray(next(iter(m.query_embed([q]))), dtype=np.float32)

    # ------------------------------------------------------------------ lifecycle
    def _artifact_dir(self) -> tuple[Path | None, str | None]:
        s = get_settings()
        if s.kb_local_path:
            return Path(s.kb_local_path), f"local folder {s.kb_local_path}"
        creds = get_credentials()
        if s.kb_artifact_uri:  # bucket (gs:// / hf:// / folder), verified like models
            import os

            from app.storage import artifacts

            if s.google_application_credentials:
                os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", s.google_application_credentials)
            store = artifacts.open_store(s.kb_artifact_uri, creds.get("hf_token"))
            remote = not isinstance(store, artifacts.LocalStore)
            got = artifacts.fetch_latest(store, "sfumato_kb", Path(s.kb_dir) / "downloads",
                                         signing_key=s.artifact_signing_key,
                                         require_signature=remote and s.ml_artifact_require_signature)
            if got is None:
                raise RuntimeError(f"No 'sfumato_kb' published in {store.describe()}")
            return got[1], f"{store.describe()}/sfumato_kb@{got[0]}"
        repo = creds.get("kb_hf_repo") or s.kb_hf_repo
        target = Path(s.kb_dir) / "artifact"
        if repo:
            try:
                from huggingface_hub import snapshot_download

                path = snapshot_download(repo_id=repo, repo_type="dataset", revision=s.kb_hf_revision,
                                         local_dir=str(target), allow_patterns=ARTIFACT_FILES,
                                         token=creds.get("hf_token") or None)
                return Path(path), f"huggingface:{repo}@{s.kb_hf_revision}"
            except Exception as e:  # offline or bad token: fall back to the last downloaded copy
                if (target / "manifest.json").exists():
                    log.warning("Knowledge base download failed (%s); using the cached copy", e)
                    return target, f"huggingface:{repo} (cached copy — download failed: {type(e).__name__})"
                raise RuntimeError(f"Cannot download {repo}: {type(e).__name__}: {e}") from e
        if (target / "manifest.json").exists():
            return target, "cached copy"
        return None, None

    def sync(self) -> dict:
        """Download (if configured) and load the knowledge base. Safe to call repeatedly."""
        s = get_settings()
        if not s.kb_enabled:
            self.state = "disabled"
            return self.status()
        with self._lock:
            try:
                self.state, self.error = "syncing", None
                artifact, source = self._artifact_dir()
                if artifact is None:
                    self.state = "not_configured"
                    return self.status()
                manifest_bytes = (artifact / "manifest.json").read_bytes()
                manifest = json.loads(manifest_bytes)
                if manifest.get("embedding_model") != s.kb_embed_model:
                    raise ValueError(f"knowledge base embedded with {manifest.get('embedding_model')}, "
                                     f"KB_EMBED_MODEL is {s.kb_embed_model}")
                version = hashlib.sha256(manifest_bytes).hexdigest()[:16]
                self.state = "loading"
                use_pg = s.kb_store == "pgvector" or (s.kb_store == "auto" and PgVectorStore.available())
                if use_pg:
                    store = PgVectorStore()
                    store.load(artifact, manifest, version)
                else:
                    store = MemoryStore(artifact, manifest)
                self.store, self.manifest, self.source = store, {**manifest, "version": version}, source
                self.loaded_at = datetime.now(timezone.utc).isoformat()
                self.state = "ready"
                log.info("Knowledge base ready: %s chunks (%s store, %s)", manifest.get("chunks"), store.name, source)
            except Exception as e:
                log.exception("Knowledge base unavailable")
                self.state, self.error = "error", f"{type(e).__name__}: {e}"
        return self.status()

    def attach(self) -> bool:
        """Worker processes: use a knowledge base already loaded into pgvector by the API process."""
        if self.ready:
            return True
        if self.state in ("syncing", "loading") or time.time() - self._last_attach < 30:
            return False
        self._last_attach = time.time()
        s = get_settings()
        if not s.kb_enabled:
            return False
        try:
            if s.kb_store != "memory" and PgVectorStore.available():
                store = PgVectorStore()
                meta = store.loaded_version()
                if meta:
                    self.store, self.manifest = store, {**meta["manifest"], "version": meta["version"]}
                    self.source, self.state = "pgvector (loaded by the API process)", "ready"
                    return True
            if s.kb_local_path or (Path(s.kb_dir) / "artifact" / "manifest.json").exists():
                return self.sync()["state"] == "ready"
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
        return False

    def start_background_sync(self) -> None:
        threading.Thread(target=self.sync, name="kb-sync", daemon=True).start()

    # ------------------------------------------------------------------ queries
    @property
    def ready(self) -> bool:
        return self.state == "ready" and self.store is not None

    def search(self, query: str, k: int | None = None, min_score: float | None = None,
               per_record: int = 2) -> list[dict]:
        if not self.ready:
            return []
        s = get_settings()
        k = k or s.kb_top_k
        min_score = s.kb_min_score if min_score is None else min_score
        t0 = time.perf_counter()
        q = self._embed_query(query)
        hits = self.store.search(q, k * 4)
        out, per = [], {}
        for h in hits:
            if h["score"] < min_score or per.get(h["record_id"], 0) >= per_record:
                continue
            per[h["record_id"]] = per.get(h["record_id"], 0) + 1
            out.append({**h, "score": round(float(h["score"]), 4)})
            if len(out) >= k:
                break
        self.latencies = (self.latencies + [(time.perf_counter() - t0) * 1000])[-100:]
        return out

    def status(self) -> dict:
        s = get_settings()
        m = self.manifest or {}
        lat = self.latencies[-50:]
        count = None
        if self.ready:
            try:
                count = self.store.count()
            except Exception:
                count = None
        return {
            "enabled": s.kb_enabled, "state": self.state, "error": self.error, "source": self.source,
            "store": self.store.name if self.store else None, "chunks": count, "records": m.get("records"),
            "embedding_model": m.get("embedding_model") or s.kb_embed_model, "dimensions": m.get("dimensions"),
            "built_at": m.get("built_at"), "loaded_at": self.loaded_at, "version": m.get("version"),
            "dataset": (m.get("source") or {}).get("repo"), "dataset_revision": (m.get("source") or {}).get("revision"),
            "license": m.get("source_license"), "domains": m.get("domains"), "stats": m.get("stats"),
            "configured_repo": get_credentials().get("kb_hf_repo") or s.kb_hf_repo, "local_path": s.kb_local_path,
            "top_k": s.kb_top_k, "min_score": s.kb_min_score,
            "avg_search_ms": round(sum(lat) / len(lat), 1) if lat else None,
        }


knowledge_base = KnowledgeBase()
