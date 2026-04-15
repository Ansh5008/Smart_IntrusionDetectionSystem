"""Room-based WebSocket connection manager."""
from __future__ import annotations
import json, logging
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self._rooms: dict[str, list[WebSocket]] = {"traffic": [], "alerts": []}

    async def connect(self, room: str, ws: WebSocket):
        await ws.accept()
        if room not in self._rooms:
            self._rooms[room] = []
        self._rooms[room].append(ws)
        logger.info("WS client joined room=%s (total=%d)", room, len(self._rooms[room]))

    def disconnect(self, room: str, ws: WebSocket):
        if room in self._rooms and ws in self._rooms[room]:
            self._rooms[room].remove(ws)
        logger.info("WS client left room=%s", room)

    async def broadcast(self, room: str, data: dict):
        if room not in self._rooms:
            return
        dead: list[WebSocket] = []
        msg = json.dumps(data, default=str)
        for ws in self._rooms[room]:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._rooms[room].remove(ws)


manager = ConnectionManager()
