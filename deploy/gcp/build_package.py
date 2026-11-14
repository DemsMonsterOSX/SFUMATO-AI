"""Build the deployment package for the GCP VM: dist/sfumato-deploy.tar.gz (+ dist/package.json with its sha256).

Contents: backend/, examples/, playbooks/, config/, ml/ (models, evaluation, datasets) and web/ (Next.js standalone build).
Nothing secret goes in: .env files, secrets/, databases and key material are excluded and the result is scanned.
Usage: python deploy/gcp/build_package.py [--skip-build]
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "dist"
OUT = DIST / "sfumato-deploy.tar.gz"
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".venv", "node_modules_cache", "tests", ".git"}
SKIP_SUFFIX = (".pyc", ".db", ".db-wal", ".db-shm", ".log", ".ipynb", ".tsbuildinfo")
SKIP_NAMES = {".env", "sfumato.db"}
PLATFORM_JUNK = re.compile(r"(win32|darwin|musl|arm64)", re.I)  # native binaries of other platforms (sharp, swc)
PRIVATE_KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def secret_values() -> list[bytes]:
    """Values from the local .env that must never end up in the package."""
    vals = []
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
            k, _, v = line.partition("=")
            if k.strip() in {"API_KEYS", "SECRET_KEY", "ARTIFACT_SIGNING_KEY", "POSTGRES_PASSWORD"} and len(v.strip()) >= 16 \
                    and not v.strip().startswith(("sfumato-dev", "change-this")):  # public placeholders shipped in config.py
                vals.append(v.strip().encode())
    return vals


def build_frontend() -> None:
    npm = "npm.cmd" if sys.platform == "win32" else "npm"
    print("== building the frontend (next build)")
    subprocess.run([npm, "run", "build"], cwd=ROOT / "frontend", check=True)


def add_tree(tar: tarfile.TarFile, src: Path, arc: str, secrets: list[bytes], filt=None) -> int:
    n = 0
    for p in sorted(src.rglob("*")):
        rel = p.relative_to(src)
        if any(part in SKIP_DIRS for part in rel.parts) or p.name in SKIP_NAMES or p.name.endswith(SKIP_SUFFIX):
            continue
        if p.name.startswith(".env"):
            continue
        if filt and not filt(rel):
            continue
        if p.is_dir() or p.is_symlink():
            continue
        data = p.read_bytes()
        if len(data) < 5_000_000 and (PRIVATE_KEY.search(data) or any(s in data for s in secrets)):
            raise SystemExit(f"REFUSED: {p} contains key material or a local secret")
        info = tarfile.TarInfo(f"{arc}/{rel.as_posix()}")
        info.size, info.mode, info.mtime = len(data), 0o644, int(p.stat().st_mtime)
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        import io
        tar.addfile(info, io.BytesIO(data))
        n += 1
    return n


def main() -> None:
    if "--skip-build" not in sys.argv:
        build_frontend()
    standalone = ROOT / "frontend" / ".next" / "standalone"
    if not (standalone / "server.js").exists():
        raise SystemExit("frontend/.next/standalone/server.js missing: run without --skip-build")
    DIST.mkdir(exist_ok=True)
    secrets = secret_values()
    keep_ml = lambda rel: rel.parts[0] in {"models", "evaluation", "datasets", "bigdata"}  # noqa: E731
    with tarfile.open(OUT, "w:gz", compresslevel=9) as tar:
        counts = {
            "backend": add_tree(tar, ROOT / "backend", "backend", secrets, lambda r: r.parts[0] != "app" or "tests" not in r.parts),
            "examples": add_tree(tar, ROOT / "examples", "examples", secrets),
            "playbooks": add_tree(tar, ROOT / "playbooks", "playbooks", secrets),
            "config": add_tree(tar, ROOT / "config", "config", secrets),
            "ml": add_tree(tar, ROOT / "ml", "ml", secrets, keep_ml),
            "web": add_tree(tar, standalone, "web", secrets, lambda r: not PLATFORM_JUNK.search(r.as_posix())),
        }
        counts["web/static"] = add_tree(tar, ROOT / "frontend" / ".next" / "static", "web/.next/static", secrets)
        counts["web/public"] = add_tree(tar, ROOT / "frontend" / "public", "web/public", secrets)
    sha = hashlib.sha256(OUT.read_bytes()).hexdigest()
    meta = {"file": OUT.name, "sha256": sha, "size": OUT.stat().st_size, "files": counts}
    (DIST / "package.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
