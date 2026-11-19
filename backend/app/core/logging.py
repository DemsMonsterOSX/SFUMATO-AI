from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    if any(getattr(h, "_sfumato", False) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler._sfumato = True  # type: ignore[attr-defined]
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root.addHandler(handler)
    try:
        from app.core import logship
        if logship.enabled():
            ls = logship.LogstashHandler("api")
            ls._sfumato = True  # type: ignore[attr-defined]
            ls.setFormatter(logging.Formatter("%(name)s: %(message)s"))
            root.addHandler(ls)
    except Exception:
        pass
    root.setLevel(level)
    for noisy in ("httpx", "httpcore", "alembic.runtime.migration"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
