"""Team accounts for the HTTPS dashboard (Caddy basic auth). Hashes only leave this machine.
  python deploy/gcp/team.py add NAME      -> creates/updates the account, prints the generated password ONCE
  python deploy/gcp/team.py remove NAME
  python deploy/gcp/team.py list
State: secrets/gcp-team.json (name -> bcrypt hash, git-ignored). Writes secrets/gcp-team.caddy for deploy.ps1.
"""
from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

import bcrypt

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "secrets" / "gcp-team.json"
CADDY = ROOT / "secrets" / "gcp-team.caddy"
ALPHABET = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def load() -> dict[str, str]:
    return json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}


def save(users: dict[str, str]) -> None:
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(users, indent=2), encoding="utf-8")
    CADDY.write_text("".join(f"{u} {h}\n" for u, h in sorted(users.items())), encoding="utf-8")


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    users = load()
    if cmd == "add":
        name = sys.argv[2].strip().lower()
        if not name or not all(c.isalnum() or c in "._-" for c in name):
            raise SystemExit("invalid name (letters, digits, . _ -)")
        pw = "".join(secrets.choice(ALPHABET) for _ in range(20))
        users[name] = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
        save(users)
        print(f"{name}\t{pw}")
    elif cmd == "remove":
        users.pop(sys.argv[2].strip().lower(), None)
        save(users)
        print("removed")
    elif cmd == "list":
        save(users)
        print("\n".join(sorted(users)) or "(none)")
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
