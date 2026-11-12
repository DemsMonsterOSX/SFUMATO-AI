"""Prompt-injection defences for content that originates from incidents or CTI providers.

Untrusted text is (1) scanned for injection patterns, (2) neutralised (control characters and
chat-template tokens removed, length capped) and (3) wrapped in clearly delimited data blocks.
The model output is then validated against the evidence book, so even a successful injection
cannot introduce findings that are not backed by real evidence, and the LLM never decides alone.
"""
from __future__ import annotations

import json
import re
from typing import Any

INJECTION_PATTERNS = [
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above) (?:instructions|prompts?|rules)",
    r"disregard (?:all |any )?(?:the )?(?:previous|prior|above|system)",
    r"forget (?:all |your )?(?:previous )?instructions",
    r"you are now (?:a|an|in)\b",
    r"\bsystem prompt\b",
    r"\bdeveloper mode\b",
    r"(?:classify|mark|label|report) (?:this|the) (?:incident|alert|activity) as (?:benign|false[ _-]?positive|legitimate|safe)",
    r"new instructions?:",
    r"<\|?(?:im_start|im_end|system|assistant)\|?>",
    r"\[/?INST\]",
    r"^\s*(?:system|assistant)\s*:",
    r"### ?(?:instruction|system)",
]
_RX = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in INJECTION_PATTERNS]
_TEMPLATE_TOKENS = re.compile(r"<\|[^|>]{1,40}\|>|\[/?INST\]|<</?SYS>>", re.IGNORECASE)


def scan(value: Any, path: str = "$") -> list[dict]:
    """Return the locations of suspected prompt-injection payloads within a JSON-like structure."""
    hits: list[dict] = []
    if isinstance(value, dict):
        for k, v in value.items():
            hits.extend(scan(v, f"{path}.{k}"))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            hits.extend(scan(v, f"{path}[{i}]"))
    elif isinstance(value, str):
        for rx in _RX:
            m = rx.search(value)
            if m:
                hits.append({"path": path, "pattern": rx.pattern, "excerpt": value[max(0, m.start() - 20): m.end() + 20]})
                break
    return hits


def neutralize(text: str, limit: int = 2000) -> str:
    text = _TEMPLATE_TOKENS.sub("[removed-token]", text)
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")
    return text if len(text) <= limit else text[:limit] + " …[truncated]"


def sanitize_tree(value: Any, limit: int = 2000) -> Any:
    if isinstance(value, dict):
        return {str(k)[:100]: sanitize_tree(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_tree(v, limit) for v in value[:100]]
    if isinstance(value, str):
        return neutralize(value, limit)
    return value


def data_block(label: str, payload: Any) -> str:
    """Wrap untrusted data so the model can tell it apart from instructions."""
    body = json.dumps(sanitize_tree(payload), ensure_ascii=False, default=str, indent=1)
    body = body.replace("<<<", "‹‹‹").replace(">>>", "›››")
    return f"<<<UNTRUSTED_DATA:{label}>>>\n{body}\n<<<END_UNTRUSTED_DATA:{label}>>>"
