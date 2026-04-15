"""FastAPI auth dependency guards."""
from __future__ import annotations
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.verifier import verify_supabase_jwt

bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> dict:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        return await verify_supabase_jwt(creds.credentials)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    role = user.get("user_metadata", {}).get("role", "analyst")
    if role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin access required")
    return user


async def require_analyst(user: dict = Depends(get_current_user)) -> dict:
    return user  # any authenticated user is at least analyst
