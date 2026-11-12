"""Versioned artifact stores: local folder, Google Cloud Storage (gs://) and Hugging Face Hub (hf://).

Standalone on purpose (standard library only; google-cloud-storage / huggingface_hub are imported lazily):
the very same file is embedded in the Kaggle notebooks that publish models and knowledge bases, and used
by the Sfumato backend to download them.

Layout inside a store::

    <name>/LATEST.json                    {"version": "20261112T101500Z"}
    <name>/<version>/ARTIFACT.json        {"meta": {name, version, created_at, files: {file: sha256}}, "signature": hmac}
    <name>/<version>/<files...>

Integrity: every file is checked against the sha256 in ARTIFACT.json, and ARTIFACT.json carries an HMAC-SHA256
signature made with a shared secret (ARTIFACT_SIGNING_KEY). Models are pickles: loading one is code execution,
so remote artifacts are refused unless the signature verifies. A tampered bucket cannot push code into Sfumato
without the signing key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ArtifactError(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ------------------------------------------------------------------------------------------------ stores
class LocalStore:
    kind = "local"

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def describe(self) -> str:
        return f"file://{self.root}"

    def read_text(self, key: str) -> str | None:
        p = self.root / key
        return p.read_text(encoding="utf-8") if p.is_file() else None

    def write_text(self, key: str, text: str) -> None:
        p = self.root / key
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def download_file(self, key: str, dest: Path) -> None:
        shutil.copyfile(self.root / key, dest)

    def upload_file(self, src: Path, key: str) -> None:
        p = self.root / key
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, p)


class GCSStore:
    kind = "gcs"

    def __init__(self, bucket: str, prefix: str = "", client=None):
        if client is None:
            try:
                from google.cloud import storage
            except ImportError as e:  # pragma: no cover
                raise ArtifactError("pip install google-cloud-storage to use gs:// stores") from e
            client = storage.Client()  # credentials: GOOGLE_APPLICATION_CREDENTIALS or the environment
        self.bucket_name, self.prefix = bucket, prefix.strip("/")
        self.bucket = client.bucket(bucket)

    def describe(self) -> str:
        return f"gs://{self.bucket_name}/{self.prefix}".rstrip("/")

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def read_text(self, key: str) -> str | None:
        blob = self.bucket.blob(self._key(key))
        return blob.download_as_text() if blob.exists() else None

    def write_text(self, key: str, text: str) -> None:
        self.bucket.blob(self._key(key)).upload_from_string(text, content_type="application/json")

    def download_file(self, key: str, dest: Path) -> None:
        self.bucket.blob(self._key(key)).download_to_filename(str(dest))

    def upload_file(self, src: Path, key: str) -> None:
        self.bucket.blob(self._key(key)).upload_from_filename(str(src))


class HFStore:
    kind = "huggingface"

    def __init__(self, repo: str, prefix: str = "", token: str | None = None):
        self.repo, self.prefix, self.token = repo, prefix.strip("/"), token

    def describe(self) -> str:
        return f"hf://{self.repo}/{self.prefix}".rstrip("/")

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def read_text(self, key: str) -> str | None:
        from huggingface_hub import hf_hub_download
        from huggingface_hub.errors import EntryNotFoundError

        try:
            p = hf_hub_download(self.repo, self._key(key), repo_type="dataset", token=self.token, force_download=True)
        except EntryNotFoundError:
            return None
        return Path(p).read_text(encoding="utf-8")

    def write_text(self, key: str, text: str) -> None:
        from huggingface_hub import HfApi

        HfApi(token=self.token).upload_file(path_or_fileobj=text.encode(), path_in_repo=self._key(key),
                                            repo_id=self.repo, repo_type="dataset")

    def download_file(self, key: str, dest: Path) -> None:
        from huggingface_hub import hf_hub_download

        shutil.copyfile(hf_hub_download(self.repo, self._key(key), repo_type="dataset", token=self.token,
                                        force_download=True), dest)

    def upload_file(self, src: Path, key: str) -> None:
        from huggingface_hub import HfApi

        api = HfApi(token=self.token)
        api.create_repo(self.repo, repo_type="dataset", private=True, exist_ok=True)
        api.upload_file(path_or_fileobj=str(src), path_in_repo=self._key(key), repo_id=self.repo, repo_type="dataset")


def open_store(uri: str, hf_token: str | None = None):
    """gs://bucket/prefix | hf://user/repo[/prefix] | file:///folder | /folder"""
    if uri.startswith("gs://"):
        bucket, _, prefix = uri[5:].partition("/")
        if not bucket:
            raise ArtifactError(f"Invalid gs:// URI: {uri}")
        return GCSStore(bucket, prefix)
    if uri.startswith("hf://"):
        parts = uri[5:].split("/")
        if len(parts) < 2:
            raise ArtifactError(f"Invalid hf:// URI (expected hf://user/repo[/prefix]): {uri}")
        return HFStore("/".join(parts[:2]), "/".join(parts[2:]), hf_token)
    return LocalStore(uri[7:] if uri.startswith("file://") else uri)


# --------------------------------------------------------------------------------------- sign / publish / fetch
def _canonical(meta: dict) -> bytes:
    return json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()


def sign(meta: dict, key: str) -> str:
    return hmac.new(key.encode(), _canonical(meta), hashlib.sha256).hexdigest()


def publish(store, name: str, folder: str | Path, signing_key: str | None = None, version: str | None = None,
            extra: dict | None = None) -> str:
    """Upload every file of `folder` as a new immutable version, then move the LATEST pointer."""
    if not SAFE_NAME.match(name):
        raise ArtifactError(f"Invalid artifact name: {name!r}")
    folder = Path(folder)
    version = version or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    files = {f.name: sha256_file(f) for f in sorted(folder.iterdir()) if f.is_file() and f.name != "ARTIFACT.json"}
    if not files:
        raise ArtifactError(f"Nothing to publish in {folder}")
    bad = [n for n in files if not SAFE_NAME.match(n)]
    if bad:
        raise ArtifactError(f"Unsupported file names: {bad}")
    meta = {"name": name, "version": version, "created_at": datetime.now(timezone.utc).isoformat(),
            "files": files, **(extra or {})}
    for fname in files:
        store.upload_file(folder / fname, f"{name}/{version}/{fname}")
    doc = {"meta": meta, "signature": sign(meta, signing_key) if signing_key else None}
    store.write_text(f"{name}/{version}/ARTIFACT.json", json.dumps(doc, indent=1))
    store.write_text(f"{name}/LATEST.json", json.dumps({"version": version}))  # last: readers never see a partial version
    return version


def fetch_latest(store, name: str, dest_root: str | Path, signing_key: str | None = None,
                 require_signature: bool = True) -> tuple[str, Path, dict] | None:
    """Download (and verify) the newest version. Returns (version, folder, meta) or None if nothing is published."""
    latest = store.read_text(f"{name}/LATEST.json")
    if latest is None:
        return None
    version = str(json.loads(latest).get("version", ""))
    if not SAFE_NAME.match(version):
        raise ArtifactError(f"Invalid version in LATEST.json: {version!r}")
    raw = store.read_text(f"{name}/{version}/ARTIFACT.json")
    if raw is None:
        raise ArtifactError(f"{name}/{version}/ARTIFACT.json is missing in {store.describe()}")
    doc = json.loads(raw)
    meta, signature = doc.get("meta") or {}, doc.get("signature")
    if meta.get("name") != name or meta.get("version") != version:
        raise ArtifactError("ARTIFACT.json does not match the requested name/version")
    if require_signature and not signing_key:
        raise ArtifactError("ARTIFACT_SIGNING_KEY is required to load remote artifacts (they contain pickles)")
    if signing_key and signature is not None:  # always verified when a key is known, even for trusted local folders
        if not hmac.compare_digest(sign(meta, signing_key), signature):
            raise ArtifactError(f"Invalid signature for {name}/{version}: artifact rejected")
    elif require_signature:
        raise ArtifactError(f"{name}/{version} is not signed: artifact rejected")
    target = Path(dest_root) / name / version
    if (target / ".verified").exists():
        return version, target, meta
    tmp = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=_ensure(Path(dest_root) / name)))
    try:
        for fname, digest in (meta.get("files") or {}).items():
            if not SAFE_NAME.match(fname):
                raise ArtifactError(f"Unsafe file name in ARTIFACT.json: {fname!r}")
            store.download_file(f"{name}/{version}/{fname}", tmp / fname)
            if sha256_file(tmp / fname) != digest:
                raise ArtifactError(f"Checksum mismatch for {fname}: artifact rejected")
        (tmp / ".verified").write_text(version, encoding="utf-8")
        if target.exists():
            shutil.rmtree(target)
        os.replace(tmp, target)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return version, target, meta


def _ensure(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p
