"""System logs REST endpoints."""
from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from auth.dependencies import require_analyst
from core.database import get_supabase

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("")
async def list_logs(
    level: str | None = Query(None),
    source: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    user: dict = Depends(require_analyst),
):
    sb = get_supabase()
    q = sb.table("system_logs").select("*").order("created_at", desc=True)
    if level:
        q = q.eq("level", level)
    if source:
        q = q.eq("source", source)
    res = q.range(offset, offset + limit - 1).execute()
    return {"data": res.data, "count": len(res.data)}
