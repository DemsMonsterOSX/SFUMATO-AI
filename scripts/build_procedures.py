"""Build the response-procedure library from ml/procedures/src/*.py.

  python scripts/build_procedures.py            writes ml/procedures/md/PROC-*.md, ml/procedures/index.json, ml/procedures/manifest.json
  python scripts/build_procedures.py --check    only validates (unique ids, required fields, ATT&CK id format)

The library is DRAFT material generated for a course project (status field in every file): not validated by a security
professional. index.json holds the full text of every procedure for the lexical (BM25) search used by the API and the agent.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "ml" / "procedures"
sys.path.insert(0, str(BASE / "src"))
TECH = re.compile(r"^T\d{4}(\.\d{3})?$")
REQUIRED = ["id", "title", "tactic", "techniques", "severity", "tags", "signals", "triage", "contain", "eradicate", "recover", "evidence", "false_positives"]
SECTIONS = [("Detection signals", "signals"), ("Triage", "triage"), ("Containment", "contain"), ("Eradication", "eradicate"),
            ("Recovery", "recover"), ("Evidence to keep", "evidence"), ("Possible false positives", "false_positives")]


def load() -> list[dict]:
    common = importlib.import_module("common")
    for m in sorted(p.stem for p in (BASE / "src").glob("part*.py")):
        importlib.import_module(m)
    return sorted(common.PROCEDURES, key=lambda p: p["id"])


def validate(procs: list[dict]) -> list[str]:
    errs, seen = [], set()
    for p in procs:
        for k in REQUIRED:
            if k not in p:
                errs.append(f"{p.get('id')}: missing {k}")
        if p["id"] in seen:
            errs.append(f"duplicate id {p['id']}")
        seen.add(p["id"])
        if p["severity"] not in {"low", "medium", "high", "critical"}:
            errs.append(f"{p['id']}: bad severity")
        for t in p["techniques"]:
            if not TECH.match(t):
                errs.append(f"{p['id']}: bad technique id {t}")
        for _, k in SECTIONS:
            if not p[k]:
                errs.append(f"{p['id']}: empty {k}")
    return errs


def to_md(p: dict) -> str:
    fm = ["---", f"id: {p['id']}", f"title: \"{p['title']}\"", f"tactic: {p['tactic']}",
          f"techniques: [{', '.join(p['techniques'])}]", f"severity: {p['severity']}", f"tags: [{', '.join(p['tags'])}]",
          f"dataset_families: [{', '.join(p['dataset_families'])}]", f"status: {p['status']}", "---", "", f"# {p['id']} {p['title']}", ""]
    body = []
    for head, key in SECTIONS:
        body += [f"## {head}"] + [f"- {x}" for x in p[key]] + [""]
    return "\n".join(fm + body)


def plain_text(p: dict) -> str:
    parts = [p["title"], p["tactic"], " ".join(p["techniques"]), " ".join(p["tags"]), " ".join(p["dataset_families"])]
    for _, k in SECTIONS:
        parts += p[k]
    return " . ".join(parts)


def main() -> None:
    procs = load()
    errs = validate(procs)
    if errs:
        print("\n".join(errs))
        raise SystemExit(f"{len(errs)} problem(s)")
    print(f"{len(procs)} procedures valid")
    if "--check" in sys.argv:
        return
    md = BASE / "md"
    md.mkdir(parents=True, exist_ok=True)
    for old in md.glob("PROC-*.md"):
        old.unlink()
    for p in procs:
        (md / f"{p['id']}.md").write_text(to_md(p), encoding="utf-8", newline="\n")
    index = [{**p, "text": plain_text(p)} for p in procs]
    raw = json.dumps(index, ensure_ascii=False, indent=1)
    (BASE / "index.json").write_text(raw, encoding="utf-8", newline="\n")
    manifest = {"count": len(procs), "built_at": datetime.now(timezone.utc).isoformat(), "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "status": "draft-generated-not-validated", "frameworks": ["NIST SP 800-61", "MITRE ATT&CK"]}
    (BASE / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8", newline="\n")
    print("written:", md, BASE / "index.json")


if __name__ == "__main__":
    main()
