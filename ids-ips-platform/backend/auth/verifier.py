"""JWKS-based JWT verification for Supabase tokens."""
from __future__ import annotations
import time, logging
from typing import Any
import httpx
from jose import jwt, JWTError
from core.config import settings

logger = logging.getLogger(__name__)

_jwks_cache: dict[str, Any] | None = None
_jwks_fetched_at: float = 0
_JWKS_TTL = 3600  # 1 hour


async def _fetch_jwks() -> dict[str, Any]:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache
    async with httpx.AsyncClient() as client:
        resp = await client.get(settings.supabase_jwks_url)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_fetched_at = now
        logger.info("JWKS fetched from Supabase")
        return _jwks_cache


async def verify_supabase_jwt(token: str) -> dict[str, Any]:
    """Decode and verify a Supabase access token. Returns the payload."""
    try:
        jwks = await _fetch_jwks()
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience="authenticated",
        )
        return payload
    except JWTError:
        # Fallback: try HS256 with JWT secret if JWKS fails
        if settings.supabase_jwt_secret:
            payload = jwt.decode(
                token,
                settings.supabase_jwt_secret,
                algorithms=["HS256"],
                audience="authenticated",
            )
            return payload
        raise
