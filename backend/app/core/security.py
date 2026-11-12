"""API authentication, rate limiting, request size limits and audit logging."""
from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import Header, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.cache import cache
from app.core.config import get_settings
from app.database.session import session_scope
from app.models import AuditLog

log = logging.getLogger("sfumato.security")
PUBLIC_PATHS = {"/api/v1/health", "/docs", "/redoc", "/openapi.json", "/"}


def key_fingerprint(key: str) -> str:
    return "key:" + hashlib.sha256(key.encode()).hexdigest()[:10]


def require_api_key(request: Request, x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    keys = get_settings().api_key_list
    supplied = x_api_key or ""
    if not supplied or not any(hmac.compare_digest(supplied, k) for k in keys):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid API key (header X-API-Key)",
                            headers={"WWW-Authenticate": "ApiKey"})
    actor = key_fingerprint(supplied)
    request.state.actor = actor
    return actor


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")


def audit(request: Request | None, action: str, target: str | None = None, details: dict | None = None) -> None:
    try:
        with session_scope() as s:
            s.add(AuditLog(actor=getattr(request.state, "actor", "anonymous") if request else "system",
                           client_ip=client_ip(request) if request else None, action=action, target=target,
                           details=details))
    except Exception:  # auditing must never break the request
        log.exception("Audit log write failed")


class RequestGuardMiddleware(BaseHTTPMiddleware):
    """Rejects oversized bodies and applies a fixed-window rate limit per client."""

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        if request.method in ("POST", "PUT", "PATCH"):
            length = request.headers.get("content-length")
            if length and int(length) > settings.max_request_bytes:
                return JSONResponse({"detail": f"Request body exceeds {settings.max_request_bytes} bytes"}, 413)
            body = await request.body()
            if len(body) > settings.max_request_bytes:
                return JSONResponse({"detail": f"Request body exceeds {settings.max_request_bytes} bytes"}, 413)
        if request.url.path not in PUBLIC_PATHS and not request.url.path.endswith("/stream"):
            ident = request.headers.get("x-api-key") or client_ip(request)
            bucket = hashlib.sha256(ident.encode()).hexdigest()[:16]
            n = cache.incr_window(f"rl:{bucket}", 60)
            if n > settings.rate_limit_per_minute:
                return JSONResponse({"detail": "Rate limit exceeded, retry in a minute"}, 429,
                                    headers={"Retry-After": "60"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response
