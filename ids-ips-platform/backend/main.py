"""CyberShield IDS/IPS — FastAPI backend."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from websocket.connection_manager import manager
from simulation.scheduler import set_ws_manager, simulation_loop, stop as stop_sim
from websocket.traffic_ws import router as traffic_ws_router
from websocket.alerts_ws import router as alerts_ws_router
from routers.traffic import router as traffic_router
from routers.alerts import router as alerts_router
from routers.logs import router as logs_router
from routers.users import router as users_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──
    logger.info("🛡️  CyberShield IDS backend starting...")
    set_ws_manager(manager)
    sim_task = asyncio.create_task(simulation_loop())
    logger.info("✅ Packet simulation started")
    yield
    # ── Shutdown ──
    stop_sim()
    sim_task.cancel()
    logger.info("🛑 Simulation stopped")


app = FastAPI(
    title="CyberShield IDS/IPS API",
    version="1.0.0",
    description="Real-time Intrusion Detection & Prevention System",
    lifespan=lifespan,
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url, "http://localhost:3000", "http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── REST Routers ──
app.include_router(traffic_router)
app.include_router(alerts_router)
app.include_router(logs_router)
app.include_router(users_router)

# ── WebSocket Routers ──
app.include_router(traffic_ws_router)
app.include_router(alerts_ws_router)


@app.get("/")
async def root():
    return {
        "service": "CyberShield IDS/IPS",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "rest": ["/api/traffic", "/api/alerts", "/api/logs", "/api/users"],
            "websocket": ["/ws/traffic", "/ws/alerts"],
        },
    }


@app.get("/health")
async def health():
    from simulation.scheduler import get_stats
    stats = get_stats()
    return {"status": "healthy", "simulation": stats}
