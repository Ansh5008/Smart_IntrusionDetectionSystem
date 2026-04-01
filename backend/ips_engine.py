from __future__ import annotations

import collections
import threading
import time
import json
import logging
from typing import Dict, Any, Deque

from backend.database import get_connection, get_setting
from backend.ips_actions import (
    block_ip_windows,
    execute_throttle_simulation,
    execute_monitor_action,
    execute_alert_action,
    get_active_blocked_ips
)

logger = logging.getLogger("IPS_Engine")

# --- In-Memory State Simulation ---
# Simulates Redis-like fast access stores
class BlockedNetworksCache:
    def __init__(self):
        self.lock = threading.RLock()
        self.blocked_ips: set[str] = set()
        self.last_sync = 0.0
        
    def sync_from_db(self):
        # Prevent hitting DB on every single packet, sync every 5 seconds
        if time.time() - self.last_sync > 5.0:
            with self.lock:
                blocks = get_active_blocked_ips()
                self.blocked_ips = {b["ip_address"] for b in blocks}
                self.last_sync = time.time()
                
    def is_blocked(self, ip: str) -> bool:
        with self.lock:
            return ip in self.blocked_ips

    def add_block(self, ip: str):
        with self.lock:
            self.blocked_ips.add(ip)

blocked_cache = BlockedNetworksCache()

# --- Dynamic Rule Configuration ---
default_rules = {
    "ddos_window_seconds": 5,
    "ddos_threshold": 100,  # packets per window
    "port_scan_limit": 10,   # unique ports per window
    "honeypot_ports": [22, 23, 445, 1433, 3389],
    "throttle_score_threshold": 50,
    "block_score_threshold": 80,
    "auto_block_enabled": False
}

class IPSConfig:
    def __init__(self):
        self.lock = threading.RLock()
        self.config = default_rules.copy()
        
    def set(self, key, value):
        with self.lock:
            self.config[key] = value
            
    def get(self, key, default=None):
        with self.lock:
            return self.config.get(key, default)
            
    def get_all(self):
        with self.lock:
            return self.config.copy()

config = IPSConfig()

# --- Stateful Tracking (Sliding Window & Behavioral Profile) ---
class IPProfile:
    def __init__(self):
        # Sliding Window (timestamps of packets)
        self.packet_timestamps: Deque[float] = collections.deque()
        self.recent_ports: set[int] = set()
        
        # Behavioral Profile
        self.total_requests = 0
        self.last_seen = 0.0
        self.risk_score = 0.0
        self.state = "NORMAL"  # NORMAL -> MONITOR -> ALERT -> THROTTLE -> BLOCK
        self.previous_flags: list[str] = []

    def cleanup_old_packets(self, current_time: float, window: int):
        while self.packet_timestamps and current_time - self.packet_timestamps[0] > window:
            self.packet_timestamps.popleft()

ip_profiles: Dict[str, IPProfile] = collections.defaultdict(IPProfile)
profiles_lock = threading.RLock()


# --- Evaluator ---
def evaluate_packet(packet_info: dict, ml_prediction: str, ml_confidence: float) -> bool:
    """
    Evaluates a packet and updates the stateful IPS engine.
    Returns True if the packet is ALLOWED (not blocked).
    Returns False if the packet should be DROPPED/BLOCKED.
    """
    src_ip = packet_info.get("src_ip")
    if not src_ip or src_ip in ("127.0.0.1", "::1", "localhost", "", "0.0.0.0"):
        return True  # Allow loopback/empty
        
    # Check if we already OS-blocked this IP.
    blocked_cache.sync_from_db()
    if blocked_cache.is_blocked(src_ip):
        return False # Physical drop emulation

    current_time = time.time()
    dst_port = packet_info.get("dst_port", 0)
    
    with profiles_lock:
        profile = ip_profiles[src_ip]
        window_sec = config.get("ddos_window_seconds", 5)
        
        # Update Slide Window
        profile.cleanup_old_packets(current_time, window_sec)
        profile.packet_timestamps.append(current_time)
        profile.recent_ports.add(dst_port)
        profile.total_requests += 1
        profile.last_seen = current_time
        
        # --- Evaluate Logic ---
        score_increment = 0.0
        action_reason = ""
        
        # 1. Honeypot check (Instakill)
        honeypot_ports = config.get("honeypot_ports", [])
        if dst_port in honeypot_ports:
            score_increment += 100.0  # Immediate block score
            action_reason = f"Access to Honeypot port {dst_port}"
            profile.previous_flags.append("HONEYPOT")
            
        # 2. ML Prediction Check
        if ml_prediction == "ATTACK":
            score_increment += 25.0 * ml_confidence
            action_reason = "ML Anomaly Detected"
            profile.previous_flags.append("ML_ATTACK")
            
        # 3. DDoS Volumetric Check
        req_rate = len(profile.packet_timestamps)
        ddos_limit = config.get("ddos_threshold", 100)
        if req_rate > ddos_limit:
            score_increment += 40.0
            action_reason = f"High Request Rate ({req_rate} pkg/{window_sec}s)"
            profile.previous_flags.append("HIGH_RATE")
            
        # 4. Port Scan Check
        port_limit = config.get("port_scan_limit", 15)
        if len(profile.recent_ports) > port_limit:
            score_increment += 30.0
            action_reason = f"Port Scan pattern ({len(profile.recent_ports)} unique)"
            profile.previous_flags.append("PORT_SCAN")
            
            # Reset port set so we don't trigger infinitely on the same scan
            profile.recent_ports.clear() 

        # Time decay for Risk Score. Slowly forgets past sins.
        # Reduce score by 2% for every packet if it's benign, otherwise add increment
        if score_increment == 0:
            profile.risk_score *= 0.99
        else:
            profile.risk_score = min(100.0, profile.risk_score + score_increment)
            
        # Evaluate Multi-Stage Response if Risk Score crosses thresholds
        throttle_thresh = config.get("throttle_score_threshold", 50)
        block_thresh = config.get("block_score_threshold", 80)
        
        # Fetch Global Autonomous Mode
        auto_mode = get_setting("auto_mode", "Manual")
        
        # State transitions
        if profile.risk_score >= block_thresh and profile.state != "BLOCK":
            profile.state = "BLOCK"
            # Auto mode triggers physical block instantly
            if auto_mode == "Auto" or config.get("auto_block_enabled", False):
                success = block_ip_windows(src_ip, action_reason or "Threat Threshold Exceeded", profile.risk_score)
                if success:
                    blocked_cache.add_block(src_ip)
                return False
            else:
                # Assisted or Manual mode only alerts/logs a recommendation
                # Analysts/Admins can thereafter manually block from the IPS tab
                execute_alert_action(src_ip, f"Block Recommended ({auto_mode} Mode)", profile.risk_score)
                return True
                
        elif profile.risk_score >= throttle_thresh and profile.state not in ("BLOCK", "THROTTLE"):
            profile.state = "THROTTLE"
            execute_throttle_simulation(src_ip, action_reason or "Suspicious Volume", profile.risk_score)
            
        elif profile.risk_score >= throttle_thresh - 15 and profile.state not in ("BLOCK", "THROTTLE", "ALERT"):
            profile.state = "ALERT"
            execute_alert_action(src_ip, "Elevated Risk", profile.risk_score)
            
        elif profile.risk_score >= throttle_thresh - 30 and profile.state == "NORMAL":
            profile.state = "MONITOR"
            execute_monitor_action(src_ip, "Minor Anomaly", profile.risk_score)
            
        # If State is THROTTLE, apply token bucket probability drop logically
        if profile.state == "THROTTLE":
            # Just token bucket simulate drop 50% of packets
            if current_time * 1000 % 2 == 0: 
                return False

    return True

def override_rule(key: str, value: Any):
    # Only allow safe casting
    if key in default_rules:
        t = type(default_rules[key])
        try:
            val = json.loads(value) if t == list else t(value)
            config.set(key, val)
        except Exception:
            pass

def inject_threat_intel(ip_address: str, severity: int = 100):
    with profiles_lock:
        profile = ip_profiles[ip_address]
        profile.risk_score = min(100.0, profile.risk_score + severity)
        profile.state = "MONITOR" # Reset to trigger next phase
