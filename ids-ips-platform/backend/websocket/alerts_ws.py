"""WebSocket endpoint for live alert streaming."""
from __future__ import annotations
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from websocket.connection_manager import manager

router = APIRouter()


@router.websocket("/ws/alerts")
async def alerts_ws(ws: WebSocket):
    await manager.connect("alerts", ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect("alerts", ws)
