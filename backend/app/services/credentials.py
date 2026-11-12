"""Optional provider credentials: environment variables, overridable from the setup screen.

Values entered in the UI are encrypted with a key derived from SECRET_KEY and are write-only
through the API (only a `configured` flag is ever returned).
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select

from app.core.config import get_settings
from app.database.session import session_scope
from app.models import ProviderCredential

MANAGED = {
    "abusech_auth_key": "abuse.ch Auth-Key (ThreatFox + URLhaus)",
    "otx_api_key": "AlienVault OTX API key",
    "opencti_url": "OpenCTI URL",
    "opencti_token": "OpenCTI API token",
    "anthropic_api_key": "Anthropic API key",
    "openai_api_key": "OpenAI-compatible API key",
    "ollama_url": "Ollama URL",
    "hf_token": "Hugging Face token (knowledge base download)",
    "kb_hf_repo": "Knowledge base repository on Hugging Face",
}


def _fernet() -> Fernet:
    key = hashlib.sha256(get_settings().secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def set_credential(name: str, value: str | None) -> None:
    if name not in MANAGED:
        raise KeyError(name)
    with session_scope() as s:
        row = s.scalar(select(ProviderCredential).where(ProviderCredential.name == name))
        if not value:
            if row:
                s.delete(row)
            return
        token = _fernet().encrypt(value.encode()).decode()
        if row:
            row.encrypted_value = token
        else:
            s.add(ProviderCredential(name=name, encrypted_value=token))


def _stored() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with session_scope() as s:
            for row in s.scalars(select(ProviderCredential)):
                try:
                    out[row.name] = _fernet().decrypt(row.encrypted_value.encode()).decode()
                except InvalidToken:
                    continue  # SECRET_KEY changed: ignore undecryptable values
    except Exception:
        pass
    return out


def get_credentials() -> dict[str, str | None]:
    settings = get_settings()
    creds: dict[str, str | None] = {n: getattr(settings, n, None) for n in MANAGED}
    creds.update({k: v for k, v in _stored().items() if v})
    return creds


def credential_status() -> list[dict]:
    settings = get_settings()
    stored = _stored()
    return [{"name": n, "label": label, "configured": bool(stored.get(n) or getattr(settings, n, None)),
             "source": "setup_screen" if stored.get(n) else ("environment" if getattr(settings, n, None) else None)}
            for n, label in MANAGED.items()]
