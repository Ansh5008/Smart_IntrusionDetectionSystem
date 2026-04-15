"""Background scheduler — generates packets, runs IDS, broadcasts via WS."""
from __future__ import annotations
import asyncio, logging
from datetime import datetime
from simulation.attack_scenarios import scenario
from ids.detector import detector
from core.database import get_supabase

logger = logging.getLogger(__name__)

_running = False
_ws_manager = None  # set by main.py at startup
_stats = {"total_packets": 0, "total_alerts": 0, "flagged": 0}


def set_ws_manager(mgr):
    global _ws_manager
    _ws_manager = mgr


def get_stats() -> dict:
    return dict(_stats)


async def _persist_alert(alert_dict: dict):
    try:
        sb = get_supabase()
        sb.table("alerts").insert({
            "severity": alert_dict["severity"],
            "attack_type": alert_dict["attack_type"],
            "src_ip": alert_dict["src_ip"],
            "dst_ip": alert_dict["dst_ip"],
            "protocol": alert_dict["protocol"],
            "port": alert_dict["port"],
            "confidence_score": alert_dict["confidence_score"],
            "rule_triggered": alert_dict["rule_triggered"],
            "packet_count": alert_dict["packet_count"],
        }).execute()
    except Exception as e:
        logger.warning("Failed to persist alert: %s", e)


async def simulation_loop():
    global _running
    _running = True
    logger.info("Packet simulation started")

    while _running:
        packets = scenario.next_batch(batch_size=5)
        for pkt in packets:
            _stats["total_packets"] += 1
            pkt_dict = pkt.model_dump(mode="json")
            pkt_dict["timestamp"] = datetime.utcnow().isoformat()

            # Run IDS
            alerts = detector.analyze(pkt)
            if alerts:
                _stats["flagged"] += 1
                pkt_dict["is_flagged"] = True

            # Broadcast packet to WS clients
            if _ws_manager:
                await _ws_manager.broadcast("traffic", pkt_dict)

            # Process alerts
            for alert in alerts:
                _stats["total_alerts"] += 1
                alert_dict = alert.model_dump(mode="json")
                alert_dict["timestamp"] = datetime.utcnow().isoformat()

                if _ws_manager:
                    await _ws_manager.broadcast("alerts", alert_dict)

                asyncio.create_task(_persist_alert(alert_dict))

        await asyncio.sleep(0.5)


def stop():
    global _running
    _running = False
