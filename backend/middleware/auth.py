"""
GAGMA Auth Middleware — API key authentication for bank partners.

Protected endpoints require X-API-Key header.
Public endpoints (UI, demo, health) remain open.

API keys are configured in .env:
    GAGMA_API_KEYS=hdfc-soc:key123abc,sbi-cert:key456def

For production: store hashed keys in database with per-key rate limits.
"""
from __future__ import annotations

import os
import hashlib
import logging
from datetime import datetime, timezone

from fastapi import Request, HTTPException, Security
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

# ── API Key Management ─────────────────────────────────

# Format: "name:key,name:key"
_raw_keys = os.getenv("GAGMA_API_KEYS", "")

# Parse into {key: name} mapping
VALID_KEYS: dict[str, str] = {}
if _raw_keys:
    for pair in _raw_keys.split(","):
        parts = pair.strip().split(":", 1)
        if len(parts) == 2:
            name, key = parts[0].strip(), parts[1].strip()
            VALID_KEYS[key] = name

# Default development key (always available, removed in production)
DEV_KEY = os.getenv("GAGMA_DEV_KEY", "gagma-dev-2026")
if DEV_KEY:
    VALID_KEYS[DEV_KEY] = "development"

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ── Public Paths (no auth required) ────────────────────

PUBLIC_PREFIXES = [
    "/",
    "/css/",
    "/js/",
    "/assets/",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/api/demo/",        # Demo scenarios are public for hackathon
    "/api/analyses",     # List view is public
    "/api/status/",      # Status polling is public (frontend needs it)
    "/api/prevent/stats", # Prevention stats are public
]

PUBLIC_EXACT = [
    "/",
    "/docs",
    "/openapi.json",
    "/redoc",
]


def is_public_path(path: str) -> bool:
    """Check if a path is public (no auth required)."""
    if path in PUBLIC_EXACT:
        return True
    for prefix in PUBLIC_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


# ── Auth Dependency ────────────────────────────────────

async def verify_api_key(request: Request, api_key: str | None = Security(api_key_header)):
    """
    Verify API key for protected endpoints.

    Usage in router:
        @router.post("/analyze", dependencies=[Depends(verify_api_key)])
    
    Or applied globally via middleware in main.py.
    """
    path = request.url.path

    # Public paths don't need auth
    if is_public_path(path):
        request.state.actor = "public"
        return

    # If no API keys configured, allow all (hackathon mode)
    if not VALID_KEYS or (len(VALID_KEYS) == 1 and "development" in VALID_KEYS.values()):
        request.state.actor = "dev-mode"
        return

    # Require API key
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key not in VALID_KEYS:
        logger.warning(f"Invalid API key attempt from {request.client.host}")
        raise HTTPException(
            status_code=403,
            detail="Invalid API key.",
        )

    # Valid key — set actor identity
    request.state.actor = VALID_KEYS[api_key]
    return


def get_actor(request: Request) -> str:
    """Get the authenticated actor name from request state."""
    return getattr(request.state, "actor", "anonymous")


# ── Security Headers Middleware ─────────────────────────

async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # HSTS only when behind HTTPS (Caddy/ALB)
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
