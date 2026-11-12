"""Evidence book: allocates stable evidence IDs and keeps every piece of evidence for an investigation."""
from __future__ import annotations

from typing import Any

from app.schemas.evidence import Evidence

PREFIX = {"cti": "EV-CTI", "behavior": "EV-BEH", "context": "EV-CTX", "ml": "EV-ML", "integrity": "EV-INT",
          "knowledge": "EV-KB"}


class EvidenceBook:
    def __init__(self) -> None:
        self._items: list[Evidence] = []
        self._counters: dict[str, int] = {}

    def add(self, category: str, **fields: Any) -> Evidence:
        prefix = PREFIX[category]
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        ev = Evidence(id=f"{prefix}-{self._counters[prefix]:03d}", category=category, **fields)
        self._items.append(ev)
        return ev

    def all(self) -> list[Evidence]:
        return list(self._items)

    def ids(self) -> set[str]:
        return {e.id for e in self._items}

    def get(self, eid: str) -> Evidence | None:
        return next((e for e in self._items if e.id == eid), None)

    def by_category(self, category: str) -> list[Evidence]:
        return [e for e in self._items if e.category == category]

    def dump(self) -> list[dict]:
        return [e.model_dump() for e in self._items]

    @classmethod
    def load(cls, items: list[dict]) -> "EvidenceBook":
        book = cls()
        for raw in items:
            ev = Evidence.model_validate(raw)
            book._items.append(ev)
            prefix = ev.id.rsplit("-", 1)[0]
            book._counters[prefix] = max(book._counters.get(prefix, 0), int(ev.id.rsplit("-", 1)[1]))
        return book
