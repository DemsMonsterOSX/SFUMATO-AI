"""LLM provider clients. All of them return a parsed JSON object (dict) or raise LLMError."""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

import httpx

from app.core.config import get_settings
from app.services.credentials import get_credentials

EXTERNAL = {"anthropic", "openai"}


class LLMError(Exception):
    pass


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.DOTALL)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            raise LLMError("Model did not return JSON")
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError as e:
            raise LLMError(f"Invalid JSON from model: {e}") from e


async def call_anthropic(system: str, user: str, schema: dict) -> tuple[dict, str]:
    s = get_settings()
    key = get_credentials().get("anthropic_api_key")
    if not key:
        raise LLMError("ANTHROPIC_API_KEY not configured")
    body = {
        "model": s.anthropic_model, "max_tokens": 4096, "temperature": 0.1, "system": system,
        "messages": [{"role": "user", "content": user}],
        "tools": [{"name": "submit_investigation", "description": "Submit the structured investigation report.",
                   "input_schema": schema}],
        "tool_choice": {"type": "tool", "name": "submit_investigation"},
    }
    async with httpx.AsyncClient(timeout=s.ai_timeout_seconds) as c:
        r = await c.post("https://api.anthropic.com/v1/messages", json=body,
                         headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
    if r.status_code != 200:
        raise LLMError(f"Anthropic HTTP {r.status_code}: {r.text[:300]}")
    for block in r.json().get("content", []):
        if block.get("type") == "tool_use":
            return block.get("input") or {}, s.anthropic_model
    raise LLMError("Anthropic response contained no tool_use block")


async def call_openai(system: str, user: str, schema: dict) -> tuple[dict, str]:
    s = get_settings()
    key = get_credentials().get("openai_api_key")
    if not key:
        raise LLMError("OPENAI_API_KEY not configured")
    body = {"model": s.openai_model, "temperature": 0.1, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system + "\n\nJSON schema:\n" + json.dumps(schema)},
                         {"role": "user", "content": user}]}
    async with httpx.AsyncClient(timeout=s.ai_timeout_seconds) as c:
        r = await c.post(s.openai_base_url.rstrip("/") + "/chat/completions", json=body,
                         headers={"Authorization": f"Bearer {key}"})
    if r.status_code != 200:
        raise LLMError(f"OpenAI-compatible HTTP {r.status_code}: {r.text[:300]}")
    return _extract_json(r.json()["choices"][0]["message"]["content"]), s.openai_model


async def call_ollama(system: str, user: str, schema: dict) -> tuple[dict, str]:
    s = get_settings()
    url = get_credentials().get("ollama_url")
    if not url:
        raise LLMError("OLLAMA_URL not configured")
    body = {"model": s.ollama_model, "stream": False, "format": schema, "options": {"temperature": 0.1, "num_ctx": 8192, "num_predict": 2048},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    async with httpx.AsyncClient(timeout=s.ai_timeout_seconds) as c:
        r = await c.post(url.rstrip("/") + "/api/chat", json=body)
    if r.status_code != 200:
        raise LLMError(f"Ollama HTTP {r.status_code}: {r.text[:300]}")
    return _extract_json(r.json().get("message", {}).get("content", "")), s.ollama_model


CALLERS = {"anthropic": call_anthropic, "openai": call_openai, "ollama": call_ollama}
_semaphores: dict[int, asyncio.Semaphore] = {}


def llm_slot() -> asyncio.Semaphore:
    """Limits concurrent generations (per event loop) so parallel investigations queue instead of timing out."""
    loop = asyncio.get_running_loop()
    if id(loop) not in _semaphores:
        _semaphores[id(loop)] = asyncio.Semaphore(max(1, get_settings().ai_max_concurrency))
    return _semaphores[id(loop)]

_status_cache: dict[str, Any] = {"at": 0.0, "value": None}


async def ollama_models(url: str) -> list[str] | None:
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            r = await c.get(url.rstrip("/") + "/api/tags")
        if r.status_code == 200:
            return [m.get("name") for m in r.json().get("models", [])]
    except Exception:
        return None
    return None


async def resolve_provider() -> dict:
    """Pick the provider to use now and explain why."""
    if _status_cache["value"] and time.time() - _status_cache["at"] < 15:
        return _status_cache["value"]
    s = get_settings()
    creds = get_credentials()
    choice = s.ai_provider
    info: dict[str, Any] = {"configured_provider": choice, "allow_external": s.ai_allow_external}
    ollama_url = creds.get("ollama_url")
    models = await ollama_models(ollama_url) if ollama_url else None
    info["ollama"] = {"url": ollama_url, "reachable": models is not None, "models": models or [],
                      "model": s.ollama_model,
                      "model_available": bool(models) and any(m.split(":")[0] == s.ollama_model.split(":")[0] and
                                                              (m == s.ollama_model or ":" not in s.ollama_model)
                                                              for m in models)}
    info["anthropic"] = {"configured": bool(creds.get("anthropic_api_key")), "model": s.anthropic_model}
    info["openai"] = {"configured": bool(creds.get("openai_api_key")), "model": s.openai_model}

    def ollama_ok() -> bool:
        return info["ollama"]["reachable"] and (info["ollama"]["model_available"] or s.ollama_model in (models or []))

    selected, reason = "deterministic", "No LLM configured or reachable"
    if choice == "deterministic":
        reason = "AI_PROVIDER=deterministic"
    elif choice == "ollama":
        selected, reason = ("ollama", "AI_PROVIDER=ollama") if ollama_ok() else \
            ("deterministic", f"Ollama unreachable or model {s.ollama_model} not pulled")
    elif choice in EXTERNAL:
        selected, reason = (choice, f"AI_PROVIDER={choice}") if info[choice]["configured"] else \
            ("deterministic", f"{choice} API key missing")
    else:  # auto: local first, external only when explicitly allowed
        if ollama_ok():
            selected, reason = "ollama", "auto: local Ollama reachable"
        elif s.ai_allow_external and info["anthropic"]["configured"]:
            selected, reason = "anthropic", "auto: external provider explicitly allowed"
        elif s.ai_allow_external and info["openai"]["configured"]:
            selected, reason = "openai", "auto: external provider explicitly allowed"
    info["selected"] = selected
    info["reason"] = reason
    info["model"] = {"ollama": s.ollama_model, "anthropic": s.anthropic_model, "openai": s.openai_model}.get(
        selected, "sfumato-deterministic-v1")
    _status_cache.update(at=time.time(), value=info)
    return info


def reset_status_cache() -> None:
    _status_cache.update(at=0.0, value=None)
