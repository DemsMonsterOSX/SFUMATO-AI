"""Loads the organisation context file (config/organization.yml)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from app.core.config import get_settings


@lru_cache
def load_org_context() -> dict:
    path = Path(get_settings().config_dir) / "organization.yml"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    data.setdefault("admin_users", [])
    data.setdefault("admin_hosts", [])
    data.setdefault("change_register", {})
    data.setdefault("approved_software", [])
    data.setdefault("sanctioned_domains", [])
    data.setdefault("noisy_detection_rules", {})
    data.setdefault("working_hours_utc", {"start": 6, "end": 19})
    return data
