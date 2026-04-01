from __future__ import annotations

import subprocess
import logging
from datetime import datetime

from backend.database import get_connection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IPS_Actions")


def block_ip_windows(ip_address: str, reason: str, risk_score: float = 0.0) -> bool:
    """Implement a hard block on Windows firewall for the given IP."""
    rule_name = f"CyberShield-Block-{ip_address}"
    # netsh advfirewall firewall add rule name="Block-IPS-X.X.X.X" dir=in action=block remoteip=X.X.X.X
    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"
    ]
    
    try:
        # Run command, capture output
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        
        if result.returncode == 0 or "already exists" in result.stdout.lower():
            logger.info(f"Successfully blocked {ip_address} in Windows Firewall.")
            _log_ips_action(ip_address, "BLOCK", reason, risk_score)
            _set_blocked_ip_db(ip_address, reason, True)
            return True
        else:
            logger.error(f"Failed to block {ip_address}: {result.stdout} {result.stderr} (Requires Admin)")
            # We still log to DB to show it in UI, but the physical block failed
            _log_ips_action(ip_address, "BLOCK_FAILED", f"OS Block Failed (No Admin?): {reason}", risk_score)
            return False
            
    except Exception as e:
        logger.error(f"Exception while blocking {ip_address}: {e}")
        return False


def unblock_ip_windows(ip_address: str) -> bool:
    """Remove a previously added block rule from Windows firewall."""
    rule_name = f"CyberShield-Block-{ip_address}"
    command = [
        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
    ]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode == 0 or "No rules match" in result.stdout:
            logger.info(f"Unblocked {ip_address} in Windows Firewall.")
            _log_ips_action(ip_address, "UNBLOCK", "Manual unblock via dashboard", 0.0)
            _set_blocked_ip_db(ip_address, "", False)
            return True
        else:
            logger.error(f"Failed to unblock {ip_address}: {result.stdout} {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Exception while unblocking {ip_address}: {e}")
        return False


def execute_throttle_simulation(ip_address: str, reason: str, risk_score: float) -> bool:
    """Simulate throttling logically and log the action."""
    logger.info(f"Throttling logic engaged for {ip_address}.")
    _log_ips_action(ip_address, "THROTTLE", reason, risk_score)
    return True


def execute_monitor_action(ip_address: str, reason: str, risk_score: float) -> bool:
    """Log an escalate to monitor action."""
    _log_ips_action(ip_address, "MONITOR", reason, risk_score)
    return True


def execute_alert_action(ip_address: str, reason: str, risk_score: float) -> bool:
    """Log an escalate to alert action."""
    _log_ips_action(ip_address, "ALERT", reason, risk_score)
    return True


def _log_ips_action(ip_address: str, action: str, reason: str, risk_score: float):
    """Log the IPS action into the local ips_logs table."""
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO ips_logs (timestamp, src_ip, action, reason, risk_score)
               VALUES (?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(), ip_address, action, reason, risk_score)
        )
        conn.commit()
    except Exception as e:
        logger.error(f"DB Log Error: {e}")
    finally:
        conn.close()


def _set_blocked_ip_db(ip_address: str, reason: str, is_active: bool):
    """Update or insert the active blocked status in the database."""
    conn = get_connection()
    try:
        if is_active:
            conn.execute(
                """INSERT INTO blocked_ips (ip_address, reason, timestamp, is_active)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(ip_address) DO UPDATE SET 
                       reason=excluded.reason, timestamp=excluded.timestamp, is_active=1""",
                (ip_address, reason, datetime.now().isoformat())
            )
        else:
            conn.execute(
                "UPDATE blocked_ips SET is_active=0 WHERE ip_address=?",
                (ip_address,)
            )
        conn.commit()
    except Exception as e:
        logger.error(f"DB Block Set Error: {e}")
    finally:
        conn.close()


def get_active_blocked_ips() -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM blocked_ips WHERE is_active=1 ORDER BY timestamp DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_ips_logs(limit: int = 50) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM ips_logs ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
