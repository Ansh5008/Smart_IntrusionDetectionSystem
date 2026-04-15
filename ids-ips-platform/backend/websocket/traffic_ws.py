"""WebSocket endpoint for live traffic streaming."""
from __future__ import annotations
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from websocket.connection_manager import manager

router = APIRouter()


@router.websocket("/ws/traffic")
async def traffic_ws(ws: WebSocket):
    await manager.connect("traffic", ws)
    try:
        while True:
            await ws.receive_text()  # keep alive
    except WebSocketDisconnect:
        manager.disconnect("traffic", ws)
