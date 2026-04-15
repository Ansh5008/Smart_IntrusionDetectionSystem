"""Alerts REST endpoints."""
from __future__ import annotations
from fastapi import APIRouter, Depends, Query, HTTPException
from auth.dependencies import require_analyst, require_admin
from core.database import get_supabase

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    user: dict = Depends(require_analyst),
):
    sb = get_supabase()
    q = sb.table("alerts").select("*").order("created_at", desc=True)
    if severity:
        q = q.eq("severity", severity)
    if status:
        q = q.eq("status", status)
    res = q.range(offset, offset + limit - 1).execute()
    return {"data": res.data, "count": len(res.data)}


@router.get("/summary")
async def alert_summary(user: dict = Depends(require_analyst)):
    sb = get_supabase()
    all_alerts = sb.table("alerts").select("severity, status, attack_type").execute()
    data = all_alerts.data or []
    total = len(data)
    by_severity = {}
    by_type = {}
    open_count = 0
    for a in data:
        s = a.get("severity", "Low")
        by_severity[s] = by_severity.get(s, 0) + 1
        t = a.get("attack_type", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1
        if a.get("status") == "open":
            open_count += 1
    return {
        "total": total,
        "open": open_count,
        "by_severity": by_severity,
        "by_type": by_type,
    }


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: str,
    status: str | None = None,
    assigned_to: str | None = None,
    user: dict = Depends(require_admin),
):
    sb = get_supabase()
    update_data = {}
    if status:
        if status not in ("open", "acknowledged", "resolved"):
            raise HTTPException(400, "Invalid status")
        update_data["status"] = status
    if assigned_to:
        update_data["assigned_to"] = assigned_to
    if not update_data:
        raise HTTPException(400, "Nothing to update")
    res = sb.table("alerts").update(update_data).eq("id", alert_id).execute()
    return {"updated": len(res.data)}
