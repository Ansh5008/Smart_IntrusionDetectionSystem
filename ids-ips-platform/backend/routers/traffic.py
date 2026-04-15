"""Traffic REST endpoints."""
from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from auth.dependencies import require_analyst
from core.database import get_supabase
from simulation.scheduler import get_stats

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


@router.get("/stats")
async def traffic_stats(user: dict = Depends(require_analyst)):
    return get_stats()


@router.get("/history")
async def traffic_history(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    user: dict = Depends(require_analyst),
):
    sb = get_supabase()
    res = sb.table("packet_metrics") \
        .select("*") \
        .order("recorded_at", desc=True) \
        .range(offset, offset + limit - 1) \
        .execute()
    return {"data": res.data, "count": len(res.data)}
