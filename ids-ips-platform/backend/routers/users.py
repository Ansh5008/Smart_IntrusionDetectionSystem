"""Users REST endpoints (admin only)."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from auth.dependencies import require_admin
from core.database import get_supabase

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("")
async def list_users(user: dict = Depends(require_admin)):
    sb = get_supabase()
    res = sb.table("profiles").select("*").execute()
    return {"data": res.data, "count": len(res.data)}
