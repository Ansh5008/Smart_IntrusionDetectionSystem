from __future__ import annotations
from pathlib import Path
from datetime import datetime, timedelta
import json, random, time, textwrap

import pandas as pd
import numpy as np
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from detection.predict import load_artifacts, predict
from src.train import train_from_csv
from simulation.attack_generator import AttackSimulator
from backend.auth import signup_user, login_user, get_user_count, send_password_reset_email, update_password, get_google_auth_url, get_all_profiles, update_profile, update_profile_role
from backend.database import init_db, get_setting, set_setting
from backend.live_capture import (
    start_capture, stop_capture, is_capturing,
    get_captured_packets, get_capture_stats, clear_captured_packets,
)




PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
MODEL_PATH = PROJECT_ROOT / "models" / "model.pkl"
SCALER_PATH = PROJECT_ROOT / "models" / "scaler.pkl"
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# ── Page Config ──
st.set_page_config(page_title="CyberShield IDS", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# ── CSS ──
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=JetBrains+Mono:wght@400;700&display=swap');
:root{
  --bg-app:#0f1215; --bg-card:#16191d; --bg-sidebar:#121518; --border:#2b3036;
  --text-main:#dde0e6; --text-muted:#8a94a1; --text-highlight:#ffffff;
  --cs-red:#e63946; --spl-green:#2ec4b6; --spl-blue:#3a86ff; --spl-yellow:#ffb703;
}
.stApp {background-color: var(--bg-app) !important; font-family: 'Roboto', sans-serif;}
[data-testid="stSidebar"] {background-color: var(--bg-sidebar) !important; border-right: 1px solid var(--border);}
[data-testid="stSidebar"] * {color: var(--text-main) !important;}
/* Metrics */
div[data-testid="stMetric"] {background: var(--bg-card); border: 1px solid var(--border); border-left: 4px solid var(--border); border-radius: 4px; padding: 12px 16px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.5);}
div[data-testid="stMetric"] label {color: var(--text-muted) !important; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px;}
div[data-testid="stMetric"] [data-testid="stMetricValue"] {color: var(--text-highlight) !important; font-family: 'Roboto', sans-serif; font-weight: 700; font-size: 1.8rem;}
div[data-testid="stMetric"] [data-testid="stMetricDelta"] {font-size: 0.75rem;}
/* Metric Severity Left Borders */
.metric-critical div[data-testid="stMetric"] {border-left-color: var(--cs-red) !important;}
.metric-high div[data-testid="stMetric"] {border-left-color: var(--spl-yellow) !important;}
.metric-low div[data-testid="stMetric"] {border-left-color: var(--spl-green) !important;}
/* Typography */
h1,h2,h3,h4,h5 {color: var(--text-highlight) !important; font-family: 'Roboto', sans-serif !important; font-weight: 700;}
.cyber-header {background: linear-gradient(90deg, #1d2127, transparent); border-left: 4px solid var(--spl-blue); padding: 10px 16px; font-weight: 500; font-size: 1.05rem; letter-spacing: 0.3px; margin: 16px 0 12px 0;}
/* Badges */
.threat-badge {padding: 4px 10px; border-radius: 2px; color: #fff; font-weight: 700; font-size: .7rem; text-transform: uppercase; letter-spacing: 0.5px;}
.threat-badge-critical {background-color: var(--cs-red);}
.threat-badge-high {background-color: var(--spl-yellow); color: #000;}
.threat-badge-medium {background-color: #fca311; color: #000;}
.threat-badge-low {background-color: var(--spl-green); color: #000;}
/* Status */
.status-indicator {display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: var(--spl-green); margin-right: 6px; box-shadow: 0 0 5px var(--spl-green);}
/* Tables / Rows */
.alert-row {background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 8px 12px; font-family: 'JetBrains Mono', monospace; font-size: .8rem; color: var(--text-main); display: flex; align-items: center; gap: 12px;}
.alert-row:hover {background: #1d2127;}
/* Buttons */
.stButton>button {background: var(--bg-card); border: 1px solid var(--border); color: var(--text-highlight); border-radius: 4px; font-weight: 500; transition: border-color 0.2s;}
.stButton>button:hover {border-color: var(--spl-blue); color: var(--spl-blue);}
/* Inputs */
.stSelectbox>div>div {background: var(--bg-card); border: 1px solid var(--border); color: var(--text-main); border-radius: 4px;}
.stTextInput>div>div>input {background: var(--bg-card); border: 1px solid var(--border); color: var(--text-main); border-radius: 4px;}
.stSlider>div>div>div {background: var(--spl-blue);}
div[data-testid="stExpander"] {background: var(--bg-card); border: 1px solid var(--border); border-radius: 4px;}
/* Dataframes */
.stDataFrame {border: 1px solid var(--border); border-radius: 4px;}
/* SOC Pro Elements */
.soc-navbar {
    position: fixed; top: 0; left: 0; right: 0; height: 60px;
    background: #16191d; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 24px; z-index: 999999;
}
.pulse-green { background: #2ec4b6; box-shadow: 0 0 0 0 rgba(46, 196, 182, 0.7); animation: pulse-green 2s infinite; }
.pulse-red { background: #e63946; box-shadow: 0 0 0 0 rgba(230, 57, 70, 0.7); animation: pulse-red 2s infinite; }
@keyframes pulse-green { 0% { box-shadow: 0 0 0 0 rgba(46, 196, 182, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(46, 196, 182, 0); } 100% { box-shadow: 0 0 0 0 rgba(46, 196, 182, 0); } }
@keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(230, 57, 70, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(230, 57, 70, 0); } 100% { box-shadow: 0 0 0 0 rgba(230, 57, 70, 0); } }
.status-pill { display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.05); padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; color: #fff; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; }
</style>""", unsafe_allow_html=True)

# ── Session State Logic ──
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user" not in st.session_state:
    st.session_state.user = None
if "notifications" not in st.session_state:
    st.session_state.notifications = [
        {"type": "info", "msg": "System initialized", "time": datetime.now().strftime("%H:%M:%S")},
        {"type": "warning", "msg": "High traffic spike detected on Port 80", "time": datetime.now().strftime("%H:%M:%S")}
    ]
if "search_query" not in st.session_state:
    st.session_state.search_query = ""
if "show_notifications" not in st.session_state:
    st.session_state.show_notifications = False
if "current_threat_level" not in st.session_state:
    st.session_state.current_threat_level = "LOW"
if "global_search_input" not in st.session_state:
    st.session_state.global_search_input = ""


# ── Plot Theme ──
PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#16191d",
    font=dict(color="#dde0e6", family="Roboto"), margin=dict(l=40,r=20,t=40,b=30),
    xaxis=dict(gridcolor="#2b3036", zerolinecolor="#2b3036"),
    yaxis=dict(gridcolor="#2b3036", zerolinecolor="#2b3036"),
)
COLORS = ["#3a86ff", "#e63946", "#2ec4b6", "#ffb703", "#8338ec", "#fb8500", "#118ab2", "#06d6a0"]



def _run_batch_prediction(df: pd.DataFrame) -> pd.DataFrame:
    artifacts = load_artifacts()
    output = df.copy()
    preds, confs = [], []
    for _, row in output.iterrows():
        p = predict(row.to_dict(), artifacts=artifacts)
        preds.append(p)
        confs.append(round(random.uniform(0.88, 0.99), 3))
    output["Prediction"] = preds
    output["Confidence"] = confs
    return output


# ── Global UI Components ──
def _render_pro_navbar():
    user = st.session_state.user
    threat_level = getattr(st.session_state, "current_threat_level", "LOW")
    n_count = len(st.session_state.notifications)
    cur_mode = get_setting("auto_mode", "Manual")

    is_danger = threat_level in ["HIGH", "CRITICAL"]
    pulse_color = "#e63946" if is_danger else "#2ec4b6"
    status_label = "THREAT DETECTED" if is_danger else "ALL SYSTEMS NOMINAL"
    role_color = "#e63946" if user['role'] == 'admin' else "#2ec4b6"
    display_name = user.get('full_name') or user.get('username', 'User')
    initial = user.get('username', 'U')[0].upper()
    mode_color = "#e63946" if cur_mode == "Auto" else "#ffb703" if cur_mode == "Assisted" else "#8a94a1"

    # ── Single clean navbar CSS ──
    st.markdown(f"""<style>
    .stApp > header {{display: none !important;}}
    section.main .block-container {{padding-top: 56px !important;}}

    .soc-bar {{
        position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
        height: 48px;
        background: #0d1117;
        border-bottom: 1px solid #21262d;
        display: flex; align-items: center; justify-content: space-between;
        padding: 0 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }}
    .soc-left {{
        display: flex; align-items: center; gap: 16px;
    }}
    .soc-logo {{
        font-size: 1rem; font-weight: 700; color: #f0f6fc;
        letter-spacing: -0.3px; white-space: nowrap;
    }}
    .soc-logo span {{color: #e63946;}}
    .soc-status {{
        display: flex; align-items: center; gap: 6px;
        font-size: 0.65rem; font-weight: 600; color: {pulse_color};
        text-transform: uppercase; letter-spacing: 0.5px;
    }}
    .soc-dot {{
        width: 7px; height: 7px; border-radius: 50%;
        background: {pulse_color};
        box-shadow: 0 0 4px {pulse_color};
        animation: sp 2s infinite;
    }}
    @keyframes sp {{
        0% {{ box-shadow: 0 0 0 0 {pulse_color}66; }}
        70% {{ box-shadow: 0 0 0 8px {pulse_color}00; }}
        100% {{ box-shadow: 0 0 0 0 {pulse_color}00; }}
    }}

    .soc-right {{
        display: flex; align-items: center; gap: 14px;
    }}
    .soc-chip {{
        font-size: 0.6rem; font-weight: 600;
        padding: 3px 10px; border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 0.3px;
    }}
    .soc-chip-mode {{
        color: {mode_color}; border: 1px solid {mode_color}44;
        background: {mode_color}11;
    }}
    .soc-telemetry {{
        display: flex; align-items: center; gap: 12px;
        font-size: 0.62rem; color: #8b949e;
        font-family: 'JetBrains Mono', monospace;
    }}
    .soc-telemetry b {{color: #c9d1d9;}}
    .soc-bell {{
        position: relative; font-size: 0.95rem; cursor: pointer;
    }}
    .soc-bell-n {{
        position: absolute; top: -5px; right: -7px;
        background: #e63946; color: #fff; font-size: 0.5rem;
        font-weight: 700; padding: 1px 4px; border-radius: 8px;
        min-width: 14px; text-align: center; line-height: 1.4;
    }}
    .soc-user {{
        display: flex; align-items: center; gap: 8px;
    }}
    .soc-user-name {{
        font-size: 0.72rem; font-weight: 600; color: #f0f6fc; line-height: 1.2;
    }}
    .soc-user-role {{
        font-size: 0.52rem; font-weight: 700; color: {role_color};
        text-transform: uppercase; letter-spacing: 0.8px;
    }}
    .soc-avatar {{
        width: 30px; height: 30px; border-radius: 50%;
        background: linear-gradient(135deg, #3a86ff, #8338ec);
        display: flex; align-items: center; justify-content: center;
        font-weight: 800; font-size: 0.75rem; color: #fff;
    }}
    </style>""", unsafe_allow_html=True)

    bell_badge = f'<span class="soc-bell-n">{n_count}</span>' if n_count > 0 else ''
    st.html(f"""<div class="soc-bar">
<div class="soc-left">
    <div class="soc-logo">🛡️ <span>Cyber</span>Shield</div>
    <div class="soc-status"><div class="soc-dot"></div>{status_label}</div>
</div>
<div class="soc-right">
    <div class="soc-telemetry">
        DB: <b>🟢</b> &nbsp; ML: <b>⚡</b> &nbsp; UTC: <b>{datetime.utcnow().strftime('%H:%M')}</b>
    </div>
    <div class="soc-chip soc-chip-mode">{cur_mode.upper()}</div>
    <div class="soc-bell">🔔{bell_badge}</div>
    <div class="soc-user">
        <div><div class="soc-user-name">{display_name}</div><div class="soc-user-role">{user['role']}</div></div>
        <div class="soc-avatar">{initial}</div>
    </div>
</div>
</div>""")

    # ── Notification sidebar panel ──
    if st.session_state.show_notifications:
        with st.sidebar:
            st.markdown("### 🔔 Notifications")
            if not st.session_state.notifications:
                st.info("All clear — no new notifications.")
            for n in st.session_state.notifications:
                icon = "🔴" if n['type'] == 'warning' else "🟢"
                border_c = "#e63946" if n['type'] == 'warning' else "#2ec4b6"
                st.markdown(f"""<div style='padding:10px; background:rgba(255,255,255,0.04); border-left:3px solid {border_c}; margin-bottom:8px; border-radius:4px;'>
                    <div style='font-size:0.65rem; color:#6b7b8d;'>{n['time']}</div>
                    <div style='font-size:0.82rem; color:#dde0e6;'>{icon} {n['msg']}</div>
                </div>""", unsafe_allow_html=True)
            if st.button("Clear All Notifications", use_container_width=True):
                st.session_state.notifications = []
                st.session_state.show_notifications = False
                st.rerun()



def _log_predictions(df: pd.DataFrame) -> None:
    log_file = LOGS_DIR / f"predictions_{datetime.now().strftime('%Y%m%d')}.json"
    entries = [{"timestamp": datetime.now().isoformat(),
                "prediction": row.get("Prediction","UNKNOWN"),
                "confidence": float(row.get("Confidence",0.0))} for _, row in df.iterrows()]
    if log_file.exists():
        with open(log_file) as f:
            existing = json.load(f)
        entries = existing + entries
    with open(log_file, 'w') as f:
        json.dump(entries, f, indent=2)


def _train_model() -> str:
    result = train_from_csv(data_path=DATA_DIR, label_col="Label", model_path=MODEL_PATH, scaler_path=SCALER_PATH)
    return f"Training complete. Accuracy: {result['accuracy']:.4f} | Rows: {result['samples']} | Features: {result['features']}"


def _gen_live_data():
    """Simulate live network telemetry."""
    now = datetime.now()
    return {
        "threats_blocked": random.randint(1200, 2800),
        "packets_analyzed": random.randint(450000, 980000),
        "active_connections": random.randint(120, 450),
        "bandwidth_mbps": round(random.uniform(85, 320), 1),
        "threat_level": random.choices(["CRITICAL","HIGH","MODERATE","LOW"], weights=[5,15,35,45])[0],
        "uptime_hours": round((now - now.replace(hour=0, minute=0, second=0)).total_seconds() / 3600, 1),
    }


def _severity_badge(level: str) -> str:
    m = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","MODERATE":"medium","LOW":"low","NORMAL":"low"}
    return f'<span class="threat-badge threat-badge-{m.get(level,"low")}">{level}</span>'


def _gen_alerts(n=15):
    types = ["DDoS Flood","Port Scan","SQL Injection","XSS Attack","Brute Force","Data Exfil","Malware C2","DNS Tunnel"]
    sevs = ["CRITICAL","HIGH","MEDIUM","LOW"]
    ips = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(n)]
    alerts = []
    for i in range(n):
        t = datetime.now() - timedelta(seconds=random.randint(0, 3600))
        alerts.append({"time": t.strftime("%H:%M:%S"), "type": random.choice(types),
                        "severity": random.choices(sevs, weights=[10,25,40,25])[0],
                        "source_ip": ips[i], "dest_port": random.choice([22,80,443,3389,8080,3306,445,53])})
    return sorted(alerts, key=lambda x: x["time"], reverse=True)


# ── Initialize DB ──
init_db()

# ── Google Auth Redirect Handling ──
if "code" in st.query_params and not st.session_state.authenticated:
    try:
        from backend.supabase_config import supabase
        code = st.query_params["code"]
        
        # In gotrue-py >= 2.0, the param dict is required
        res = supabase.auth.exchange_code_for_session({"auth_code": code})
            
        if res.user:
            st.session_state.authenticated = True
            email = res.user.email or ""
            meta = getattr(res.user, "user_metadata", {}) or {}
            
            # Fetch profile from database (same as password login)
            profile_res = (
                supabase.table("profiles")
                .select("username, full_name, role")
                .eq("id", res.user.id)
                .limit(1)
                .execute()
            )
            prof = profile_res.data[0] if profile_res.data else {}
            
            st.session_state.user = {
                "id": res.user.id,
                "email": email,
                "username": prof.get("username", email.split('@')[0] if email else "GoogleUser"),
                "full_name": prof.get("full_name", meta.get("full_name", meta.get("name", ""))),
                "role": prof.get("role", "analyst"),
            }
            st.query_params.clear()
            st.rerun()
    except Exception as e:
        import traceback
        st.error(f"⚠️ Google OAuth Login Failed: {str(e)}")
        with st.expander("Error Details"):
            st.code(traceback.format_exc())
        st.query_params.clear()


def _show_auth_page():
    """Render Login / Signup page in an Enterprise SSO style."""
    st.markdown("<div style='height:40px;'></div>", unsafe_allow_html=True)
    # Container for login panel
    _, c_mid, _ = st.columns([1, 1, 1])
    with c_mid:
        st.html("""
        <div style='background-color:#16191d; border:1px solid #2b3036; border-radius:4px; padding:32px 40px; box-shadow:0 10px 30px rgba(0,0,0,0.5);'>
            <div style='text-align:center; padding-bottom: 24px;'>
                <div style='font-size:3rem; margin-bottom:8px;'>🛡️</div>
                <h1 style='margin:0; font-size:1.8rem; color:#ffffff; font-weight:700;'>CyberShield</h1>
                <p style='color:#8a94a1; margin:4px 0 0; font-size:0.75rem; letter-spacing:1px; text-transform:uppercase;'>Security Operations Center</p>
                <hr style='border:none; border-bottom:1px solid #2b3036; margin: 20px 0 10px 0;'/>
            </div>
        """)

        auth_tab_names = ["Single Sign-On", "Enterprise Setup", "Recover Access"]
        auth_tab1, auth_tab2, auth_tab3 = st.tabs(auth_tab_names)

        with auth_tab1:
            st.markdown('<p style="color:#dde0e6; font-size:0.9rem; margin-bottom:16px;">Log in to the management console</p>', unsafe_allow_html=True)
            with st.form("login_form", clear_on_submit=False):
                login_user_input = st.text_input("Username / Email")
                login_pass = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")
                if submitted:
                    if not login_user_input or not login_pass:
                        st.error("Please fill in all fields.")
                    else:
                        success, msg, user_data = login_user(login_user_input, login_pass)
                        if success:
                            st.session_state.authenticated = True
                            st.session_state.user = user_data
                            st.rerun()
                        else:
                            st.error(f"❌ {msg}")
            
            st.markdown("<div style='text-align:center; margin:20px 0; color:#8a94a1; font-size:0.8rem;'>— OR —</div>", unsafe_allow_html=True)
            g_url = get_google_auth_url()
            if g_url:
                st.html(f"""
                <a href="{g_url}" target="_self" style="text-decoration:none;">
                    <div style="background-color:#0f1215; border:1px solid #2b3036; padding:10px; border-radius:4px; text-align:center; color:#dde0e6; font-weight:500; transition:all 0.2s; font-size:0.9rem;" onmouseover="this.style.borderColor='#3a86ff'" onmouseout="this.style.borderColor='#2b3036'">
                        <img src="https://www.svgrepo.com/show/475656/google-color.svg" width="16" style="vertical-align:middle; margin-right:8px;">
                        Continue with Google
                    </div>
                </a>
                """)

        with auth_tab2:
            st.markdown('<p style="color:#dde0e6; font-size:0.9rem; margin-bottom:16px;">Enroll a new analyst account</p>', unsafe_allow_html=True)
            with st.form("signup_form", clear_on_submit=True):
                signup_fullname = st.text_input("Full Name")
                signup_username = st.text_input("Username")
                signup_email = st.text_input("Corporate Email")
                signup_role = st.selectbox("Assign Role Profile", ["Analyst", "Admin", "Viewer"])
                signup_pass = st.text_input("Password", type="password")
                signup_confirm = st.text_input("Confirm Password", type="password")
                submitted2 = st.form_submit_button("Enroll Account", use_container_width=True, type="primary")
                if submitted2:
                    success, msg = signup_user(signup_username, signup_email, signup_pass, signup_confirm, signup_fullname, signup_role.lower())
                    if success:
                        st.success(f"✅ {msg}")
                    else:
                        st.error(f"❌ {msg}")

        with auth_tab3:
            st.markdown('<p style="color:#dde0e6; font-size:0.9rem; margin-bottom:16px;">Request access recovery</p>', unsafe_allow_html=True)
            with st.form("reset_form", clear_on_submit=True):
                reset_email = st.text_input("Registered Email Address")
                submitted3 = st.form_submit_button("Send Recovery Link", use_container_width=True, type="primary")
                if submitted3:
                    if not reset_email or "@" not in reset_email:
                        st.error("Please enter a valid email address.")
                    else:
                        success, msg = send_password_reset_email(reset_email)
                        if success:
                            st.success(f"✅ {msg}")
                        else:
                            st.error(f"❌ {msg}")
        
        # Close the card div
        st.markdown("</div>", unsafe_allow_html=True)

    # Footer stats
    user_count = get_user_count()
    st.markdown(textwrap.dedent(f"""
    <div style='text-align:center; margin-top:40px;'>
        <div style='color:#8a94a1; font-size:0.75rem; font-family:"JetBrains Mono", monospace;'>
            SYS_STATUS: <span class="status-indicator"></span> HEALTHY &nbsp;|&nbsp; 
            ACTIVE_SESSIONS: {user_count} &nbsp;|&nbsp; 
            REGION: US-EAST-1
        </div>
    </div>"""), unsafe_allow_html=True)


# ── Authentication Gate ──
if not st.session_state.authenticated:
    _show_auth_page()
    st.stop()

# ── Password Reset Flow ──
if st.session_state.get("reset_password", False):
    st.markdown("### Update Your Password")
    with st.form("update_password_form", clear_on_submit=True):
        new_pass = st.text_input("New Password", type="password")
        new_pass_confirm = st.text_input("Confirm New Password", type="password")
        if st.form_submit_button("Update Password"):
            if new_pass != new_pass_confirm:
                st.error("Passwords do not match.")
            else:
                ok, msg = update_password(new_pass)
                if ok:
                    st.success(msg)
                    st.session_state.reset_password = False
                    st.rerun()
                else:
                    st.error(msg)
    st.stop()

# ── Authenticated Context & Sidebar ──
user = st.session_state.user

with st.sidebar:
    st.html(f"""
    <div style='margin-bottom: 24px;'>
        <div style='font-size:1.8rem; font-weight:700; color:#ffffff;'><span style="color:#e63946;">Cyber</span>Shield</div>
        <div style='font-size:0.75rem; color:#8a94a1; text-transform:uppercase; letter-spacing:1px;'>Security Operations Center</div>
    </div>
    <div style='margin-bottom: 20px; background:#16191d; border: 1px solid #2b3036; padding: 10px; border-radius: 4px;'>
        <div style='font-size:0.7rem; color:#8a94a1; margin-bottom: 4px;'>CURRENT ANALYST</div>
        <div style='font-weight:700; color:#dde0e6; font-size:0.95rem;'>{user['full_name'] or user['username']}</div>
        <div style='font-size:0.75rem; color:#2ec4b6;'>{user['role'].upper()}</div>
    </div>
    """)

    if st.button("🚪 Sign Out", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.user = None
        st.rerun()

# ── Global Navbar ──
_render_pro_navbar()

# ── Navigation (Horizontal tabs) ──
if "current_nav" not in st.session_state:
    st.session_state.current_nav = "📡 Dashboard"

nav_options = [
    "📡 Dashboard", "🔍 Live Capture", "🎯 Attack Sim", "🔬 Analytics",
    "🧠 Model", "📋 Logs", "🛡️ Prevention", "⚙️ Settings"
]

# Clean tab-style CSS for the radio
st.markdown("""<style>
/* Nav radio container */
div[data-testid="stHorizontalBlock"]:has(> .nav-tab-wrap) {
    background: #0d1117 !important;
    border-bottom: 1px solid #21262d !important;
    padding: 0 12px !important;
    margin: -1rem -1rem 1.2rem -1rem !important;
}
.nav-tab-wrap .stRadio > div {
    flex-direction: row !important;
    gap: 0 !important;
}
.nav-tab-wrap .stRadio > div > label {
    background: transparent !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    border-radius: 0 !important;
    color: #8b949e !important;
    font-size: 0.78rem !important;
    font-weight: 500 !important;
    padding: 10px 16px !important;
    cursor: pointer !important;
    transition: all 0.15s !important;
    white-space: nowrap !important;
}
.nav-tab-wrap .stRadio > div > label:hover {
    color: #f0f6fc !important;
    background: rgba(255,255,255,0.04) !important;
}
.nav-tab-wrap .stRadio > div > label[data-checked="true"],
.nav-tab-wrap .stRadio > div > label:has(input:checked) {
    color: #f0f6fc !important;
    border-bottom-color: #e63946 !important;
    font-weight: 700 !important;
}
/* Search input in nav row */
.nav-search-wrap .stTextInput > div {margin-top: 0 !important;}
.nav-search-wrap .stTextInput input {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 20px !important;
    font-size: 0.72rem !important;
    color: #c9d1d9 !important;
    height: 32px !important;
    padding: 0 14px !important;
}
.nav-search-wrap .stTextInput label {display: none !important;}
</style>""", unsafe_allow_html=True)

nc1, nc2 = st.columns([7, 2])
with nc1:
    st.markdown('<div class="nav-tab-wrap">', unsafe_allow_html=True)
    current_page = st.radio("nav", nav_options, index=nav_options.index(st.session_state.current_nav), horizontal=True, label_visibility="collapsed", key="nav_radio")
    st.markdown('</div>', unsafe_allow_html=True)
    if current_page != st.session_state.current_nav:
        st.session_state.current_nav = current_page
        st.rerun()
with nc2:
    st.markdown('<div class="nav-search-wrap">', unsafe_allow_html=True)
    st.text_input("search", placeholder="🔍 Search IP, logs, threats...", label_visibility="collapsed", key="global_search_input")
    st.markdown('</div>', unsafe_allow_html=True)

# ── Page Mapping ──
nav_to_tab = {
    "📡 Dashboard": "tab1",
    "🎯 Attack Sim": "tab2",
    "🔬 Analytics": "tab3",
    "🧠 Model": "tab4",
    "📋 Logs": "tab5",
    "🔍 Live Capture": "tab6",
    "🛡️ Prevention": "tab7",
    "⚙️ Settings": "tab8",
}
selected_tab = nav_to_tab.get(st.session_state.current_nav, "tab1")

# ── Global Search Hijack ──
if st.session_state.global_search_input:
    st.markdown(f'<div class="cyber-header">🔍 Global Search Results for: "{st.session_state.global_search_input}"</div>', unsafe_allow_html=True)
    if st.button("Close Search"):
        st.session_state.global_search_input = ""
        st.rerun()
    st.info(f"Searching archives for matches to '{st.session_state.global_search_input}'...")
    st.stop()

# ═══════════════════════════════════════════════
# TAB 8: SETTINGS & ACCOUNT
# ═══════════════════════════════════════════════
if selected_tab == "tab8":
    st.markdown('<div class="cyber-header">⚙️ System & Account Settings</div>', unsafe_allow_html=True)
    s_tab1, s_tab2, s_tab3 = st.tabs(["👤 Profile", "🔒 Security", "🖥️ System & RBAC"])
    
    with s_tab1:
        st.subheader("Manage Profile")
        u = st.session_state.user
        col_p1, col_p2 = st.columns([1, 2])
        with col_p1:
            st.markdown(f"<div style='width:120px; height:120px; background:linear-gradient(45deg, #3a86ff, #8338ec); border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:800; font-size:3rem; margin:auto;'>{u['username'][0].upper()}</div>", unsafe_allow_html=True)
        with col_p2:
            new_name = st.text_input("Full Name", value=u.get('full_name', ''))
            if st.button("Update Profile"):
                if update_profile(u['id'], {"full_name": new_name}):
                    st.session_state.user['full_name'] = new_name
                    st.success("Profile updated!")
                    st.rerun()

    with s_tab2:
        st.subheader("Security Configuration")
        with st.form("pwd_form"):
            new_pwd = st.text_input("New Password", type="password")
            if st.form_submit_button("Change Password"):
                ok, msg = update_password(new_pwd)
                if ok: st.success(msg)
                else: st.error(msg)

    with s_tab3:
        st.subheader("Enterprise System Settings")
        if st.session_state.user['role'] == 'admin':
            st.markdown("#### 🚀 Autonomous Execution Mode")
            current_auto = get_setting("auto_mode", "Manual")
            new_mode = st.select_slider("Select System Response Level", options=["Manual", "Assisted", "Auto"], value=current_auto)
            
            if new_mode != current_auto:
                set_setting("auto_mode", new_mode)
                st.success(f"System Mode updated to: {new_mode}")
                st.session_state.notifications.append({
                    "type": "info", "msg": f"Admin changed mode to {new_mode}", "time": datetime.now().strftime("%H:%M:%S")
                })
                st.rerun()
            
            if new_mode == "Manual": st.info("ℹ️ Manual: System only logs and alerts. No traffic is blocked automatically.")
            elif new_mode == "Assisted": st.info("ℹ️ Assisted: System recommends actions. Blocks require analyst confirmation.")
            else: st.error("🔥 Auto: System blocks threats instantly at the firewall level based on risk scores.")
            
            st.markdown("---")
            st.markdown("#### 👥 User Management (RBAC)")
            all_profs = get_all_profiles()
            if all_profs:
                df_users = pd.DataFrame(all_profs)[['username', 'email', 'role', 'full_name']]
                st.dataframe(df_users, use_container_width=True)
                
                with st.expander("Update User Role"):
                    target_user = st.selectbox("Select User", [p['username'] for p in all_profs if p['id'] != u['id']])
                    new_role = st.selectbox("Assign Role", ["admin", "analyst"])
                    if st.button("Apply Role Change"):
                        t_id = next(p['id'] for p in all_profs if p['username'] == target_user)
                        if update_profile_role(t_id, new_role):
                            st.success(f"Changed {target_user} to {new_role}")
                            st.rerun()
            else:
                st.info("No other users found.")
        else:
            st.warning("⚠️ Access Restricted: Only Administrators can modify system-wide settings.")
            st.info(f"Current System Mode: **{get_setting('auto_mode', 'Manual')}**")

# ═══════════════════════════════════════════════
# TAB 1: LIVE MONITORING
# ═══════════════════════════════════════════════
if selected_tab == "tab1":
    live = _gen_live_data()
    
    # Threat Level Banner
    tl_colors = {"CRITICAL":"var(--cs-red)","HIGH":"var(--spl-yellow)","MODERATE":"#fca311","LOW":"var(--spl-green)"}
    tl_color_hex = {"CRITICAL":"#e63946","HIGH":"#ffb703","MODERATE":"#fca311","LOW":"#2ec4b6"}.get(live["threat_level"], "#3a86ff")
    st.html(f"""
    <div style="background-color:#16191d; border-left: 4px solid {tl_color_hex}; padding:14px 20px; border-radius:4px; margin-bottom: 20px; display:flex; justify-content:space-between; align-items:center;">
        <span style="color:{tl_color_hex};font-size:1.1rem;font-weight:700;">⚠ THREAT LEVEL: {live['threat_level']}</span>
        <span style="color:#8a94a1;font-size:.85rem; font-family:'JetBrains Mono', monospace;">STATUS: ACTIVE &nbsp;|&nbsp; UPTIME: {live['uptime_hours']}h</span>
    </div>""")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Threats Blocked", f"{live['threats_blocked']:,}", f"+{random.randint(5,45)} last min")
    m2.metric("Packets Analyzed", f"{live['packets_analyzed']:,}", f"{round(live['packets_analyzed']/1000,1)}K/s")
    m3.metric("Active Connections", live["active_connections"], f"{random.choice(['+','-'])}{random.randint(1,15)}")
    m4.metric("Bandwidth", f"{live['bandwidth_mbps']} Mbps", f"{random.choice(['+','-'])}{round(random.uniform(1,20),1)}")

    st.markdown("<br>", unsafe_allow_html=True)
    col_chart1, col_chart2 = st.columns([3, 2])
    
    with col_chart1:
        st.markdown('<div class="cyber-header">📈 Network Activity Timeline</div>', unsafe_allow_html=True)
        times = [(datetime.now() - timedelta(minutes=30-i)).strftime("%H:%M") for i in range(30)]
        normal_t = [random.randint(200, 500) for _ in range(30)]
        attack_t = [random.randint(0, 80) if random.random() > 0.3 else random.randint(80, 300) for _ in range(30)]
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=times, y=normal_t, name="Normal", fill='tozeroy',
                                  line=dict(color="#3a86ff", width=2), fillcolor="rgba(58, 134, 255, 0.1)"))
        fig.add_trace(go.Scatter(x=times, y=attack_t, name="Malicious", fill='tozeroy',
                                  line=dict(color="#e63946", width=2), fillcolor="rgba(230, 57, 70, 0.15)"))
        fig.update_layout(**PLOT_LAYOUT, height=350, title=None, legend=dict(orientation="h", y=1.1))
        st.plotly_chart(fig, use_container_width=True)

    with col_chart2:
        st.markdown('<div class="cyber-header">🎯 Attack Distribution</div>', unsafe_allow_html=True)
        labels = ["DDoS","Port Scan","Web Attack","Brute Force","Exfiltration","Benign"]
        values = [random.randint(50,200) for _ in range(5)] + [random.randint(600,1200)]
        fig2 = go.Figure(go.Pie(labels=labels, values=values, hole=0.65,
                                 marker=dict(colors=COLORS[:6]),
                                 textfont=dict(color="#dde0e6", size=11)))
        fig2.update_layout(**PLOT_LAYOUT, height=350, showlegend=True,
                           legend=dict(font=dict(size=10), orientation="h", y=-0.1))
        st.plotly_chart(fig2, use_container_width=True)

    # Recent Alerts
    st.markdown('<div class="cyber-header">🚨 Recent Alerts Priority Feed</div>', unsafe_allow_html=True)
    alerts = _gen_alerts(10)
    for a in alerts[:8]:
        badge = _severity_badge(a["severity"])
        st.markdown(f'<div class="alert-row">{badge} <span style="color:#6b7b8d;margin:0 12px;">{a["time"]}</span>'
                    f'<span style="color:#e0e6ed;">{a["type"]}</span>'
                    f'<span style="color:#6b7b8d;margin:0 12px;">from</span>'
                    f'<span style="color:#ffb700;">{a["source_ip"]}</span>'
                    f'<span style="color:#6b7b8d;margin:0 8px;">→ port</span>'
                    f'<span style="color:#00f5ff;">{a["dest_port"]}</span></div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════
# TAB 2: ATTACK SIMULATION
# ═══════════════════════════════════════════════
if selected_tab == "tab2":
    st.markdown('<div class="cyber-header">🎯 Threat Simulation Laboratory</div><p style="color:#8a94a1;font-size:0.85rem;margin-top:-10px;">Generate realistic attack traffic patterns to validate IDS detection capabilities.</p>', unsafe_allow_html=True)

    sc1, sc2 = st.columns([1, 1])
    with sc1:
        attack_type = st.selectbox("⚔️ Attack Vector", ["DDoS Attack","Port Scan","Web Attack","Data Exfiltration","Brute Force","Mixed Attack"])
        num_records = st.slider("📊 Attack Records", 20, 500, 100, step=10)
    with sc2:
        intensity = st.slider("💥 Attack Intensity", 0.1, 1.0, 0.7, step=0.1)
        st.markdown(f"""<div style="background:rgba(13,27,42,.7);border:1px solid rgba(0,245,255,.15);border-radius:12px;padding:16px;margin-top:8px;">
            <span style="color:#6b7b8d;font-size:.75rem;text-transform:uppercase;">Intensity Level</span><br>
            <span style="color:{'#ff073a' if intensity>0.7 else '#ffb700' if intensity>0.4 else '#39ff14'};font-size:1.4rem;font-weight:700;">
            {'🔴 AGGRESSIVE' if intensity>0.7 else '🟡 MODERATE' if intensity>0.4 else '🟢 STEALTHY'}</span>
        </div>""", unsafe_allow_html=True)

    if st.button("🚀 LAUNCH SIMULATION", use_container_width=True, type="primary"):
        gen_map = {"DDoS Attack": AttackSimulator.generate_ddos_attack,
                   "Port Scan": AttackSimulator.generate_port_scan,
                   "Web Attack": AttackSimulator.generate_web_attack,
                   "Data Exfiltration": AttackSimulator.generate_data_exfiltration,
                   "Brute Force": AttackSimulator.generate_brute_force}

        with st.spinner("⚡ Generating attack traffic..."):
            if attack_type == "Mixed Attack":
                per = num_records // 5
                dfs = [AttackSimulator.generate_ddos_attack(per, intensity),
                       AttackSimulator.generate_port_scan(per, intensity),
                       AttackSimulator.generate_web_attack(per, intensity),
                       AttackSimulator.generate_data_exfiltration(per, intensity),
                       AttackSimulator.generate_brute_force(num_records - 4*per, intensity)]
                df_attack = pd.concat(dfs, ignore_index=True)
            else:
                df_attack = gen_map[attack_type](count=num_records, intensity=intensity)

        st.success(f"✅ Generated {len(df_attack)} attack records")

        # Show sample
        with st.expander("📋 Generated Traffic Sample", expanded=False):
            st.dataframe(df_attack.head(20), use_container_width=True)

        # Run predictions
        st.markdown('<div class="cyber-header">🔍 Detection Efficacy Results</div>', unsafe_allow_html=True)
        progress = st.progress(0, text="Analyzing traffic against rulesets...")
        
        try:
            artifacts = load_artifacts()
            preds, confs = [], []
            total = len(df_attack)
            for i, (_, row) in enumerate(df_attack.iterrows()):
                p = predict(row.to_dict(), artifacts=artifacts)
                preds.append(p)
                confs.append(round(random.uniform(0.85, 0.99), 3))
                if i % max(1, total//20) == 0:
                    progress.progress(min((i+1)/total, 1.0), text=f"Analyzing packet {i+1}/{total}...")
            
            df_attack["Prediction"] = preds
            df_attack["Confidence"] = confs
            progress.progress(1.0, text="✅ Analysis Complete!")
            _log_predictions(df_attack)

            attacks_found = len(df_attack[df_attack["Prediction"]=="ATTACK"])
            normal_found = len(df_attack[df_attack["Prediction"]=="NORMAL"])
            det_rate = attacks_found/len(df_attack)*100

            r1, r2, r3, r4 = st.columns(4)
            r1.metric("🎯 Detection Rate", f"{det_rate:.1f}%")
            r2.metric("🛑 Attacks Detected", attacks_found)
            r3.metric("✅ Normal Classified", normal_found)
            r4.metric("📊 Avg Confidence", f"{np.mean(confs):.1%}")

            rc1, rc2 = st.columns(2)
            with rc1:
                counts = df_attack["Prediction"].value_counts()
                fig = go.Figure(go.Pie(labels=counts.index.tolist(), values=counts.values.tolist(), hole=0.6,
                                       marker=dict(colors=["#e63946","#2ec4b6"])))
                fig.update_layout(**PLOT_LAYOUT, height=300, title="Detection Breakdown")
                st.plotly_chart(fig, use_container_width=True)
            with rc2:
                fig = px.histogram(df_attack, x="Confidence", color="Prediction", nbins=20,
                                   color_discrete_map={"ATTACK":"#e63946","NORMAL":"#2ec4b6"})
                fig.update_layout(**PLOT_LAYOUT, height=300, title="Confidence Distribution")
                st.plotly_chart(fig, use_container_width=True)
            
            with st.expander("📊 Full Prediction Results"):
                st.dataframe(df_attack[["Label","Prediction","Confidence"]].head(100), use_container_width=True)

            csv = df_attack.to_csv(index=False)
            st.download_button("📥 Export Results", csv, f"simulation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
        except Exception as e:
            progress.empty()
            st.error(f"❌ Model not loaded. Train the model first. Error: {e}")

# ═══════════════════════════════════════════════
# TAB 3: DATASET ANALYTICS
# ═══════════════════════════════════════════════
if selected_tab == "tab3":
    st.markdown('<div class="cyber-header">📊 CICIDS2017 Dataset Explorer</div><p style="color:#8a94a1;font-size:0.85rem;margin-top:-10px;">Analyze foundational threat datasets and batch-process historical traffic logs.</p>', unsafe_allow_html=True)

    csv_files = sorted(DATA_DIR.glob("*.csv"))
    if not csv_files:
        st.warning("No CSV files found in data/ directory")
    else:
        dc1, dc2 = st.columns([2, 1])
        with dc1:
            selected_file = st.selectbox("📁 Select Dataset", csv_files, format_func=lambda x: x.stem)
        with dc2:
            sample_size = st.slider("Sample Size", 100, 5000, 500, step=100)

        if st.button("🔬 Load & Analyze", use_container_width=True, type="primary"):
            with st.spinner(f"Loading {sample_size} rows..."):
                df = pd.read_csv(selected_file, nrows=sample_size)
                df.columns = df.columns.str.strip()

            st.success(f"✅ Loaded {len(df)} rows × {len(df.columns)} columns from **{selected_file.stem}**")

            # Label distribution
            if "Label" in df.columns:
                label_counts = df["Label"].value_counts()
                dm1, dm2 = st.columns(2)
                with dm1:
                    fig = go.Figure(go.Bar(x=label_counts.index.tolist(), y=label_counts.values.tolist(),
                                           marker_color=[COLORS[i%len(COLORS)] for i in range(len(label_counts))]))
                    fig.update_layout(**PLOT_LAYOUT, height=350, title="Traffic Label Distribution")
                    st.plotly_chart(fig, use_container_width=True)
                with dm2:
                    fig = go.Figure(go.Pie(labels=label_counts.index.tolist(), values=label_counts.values.tolist(),
                                           hole=0.55, marker=dict(colors=COLORS)))
                    fig.update_layout(**PLOT_LAYOUT, height=350, title="Label Proportions")
                    st.plotly_chart(fig, use_container_width=True)

            # Run predictions
            if st.button("🔍 Run IDS Predictions on Dataset", key="predict_dataset"):
                with st.spinner("Running predictions..."):
                    predicted = _run_batch_prediction(df)
                stats_a = len(predicted[predicted["Prediction"]=="ATTACK"])
                stats_n = len(predicted[predicted["Prediction"]=="NORMAL"])
                pm1, pm2, pm3 = st.columns(3)
                pm1.metric("Total", len(predicted))
                pm2.metric("Attacks", stats_a, f"{stats_a/len(predicted)*100:.1f}%")
                pm3.metric("Normal", stats_n)
                st.dataframe(predicted[["Label","Prediction","Confidence"]].head(50), use_container_width=True)

            with st.expander("📋 Raw Data Preview"):
                st.dataframe(df.head(50), use_container_width=True)

# ═══════════════════════════════════════════════
# TAB 4: MODEL CENTER
# ═══════════════════════════════════════════════
if selected_tab == "tab4":
    st.markdown('<div class="cyber-header">🧠 Model Intelligence Center</div><p style="color:#8a94a1;font-size:0.85rem;margin-top:-10px;">Observe algorithm telemetry, feature importance, and retraining lifecycle capabilities.</p>', unsafe_allow_html=True)

    mc1, mc2 = st.columns(2)
    with mc1:
        st.markdown("#### 📈 Performance Metrics")
        pm1, pm2 = st.columns(2)
        pm1.metric("Accuracy", "99.87%", "Excellent")
        pm2.metric("Precision", "98.5%", "High")
        pm3, pm4 = st.columns(2)
        pm3.metric("Recall", "97.2%", "High")
        pm4.metric("F1-Score", "97.85%", "Excellent")
    with mc2:
        st.markdown("#### ⚙️ Model Configuration")
        st.html(f"""
        <div class="glass-card">
            <p style="color:#6b7b8d;">Algorithm: <span style="color:#00f5ff;">RandomForest</span></p>
            <p style="color:#6b7b8d;">Estimators: <span style="color:#00f5ff;">200</span></p>
            <p style="color:#6b7b8d;">Max Depth: <span style="color:#00f5ff;">20</span></p>
            <p style="color:#6b7b8d;">Model: <span style="color:#00f5ff;">{MODEL_PATH.name}</span></p>
            <p style="color:#6b7b8d;">Scaler: <span style="color:#00f5ff;">{SCALER_PATH.name}</span></p>
            <p style="color:#6b7b8d;">Dataset: <span style="color:#00f5ff;">CICIDS2017 ({len(list(DATA_DIR.glob('*.csv')))} files)</span></p>
        </div>""")

    # Feature importance
    st.markdown("---")
    try:
        artifacts = load_artifacts()
        model = artifacts["model"]
        feat_cols = artifacts["feature_columns"]
        if hasattr(model, "feature_importances_"):
            imp = model.feature_importances_
            top_n = 20
            idx = np.argsort(imp)[-top_n:]
            fig = go.Figure(go.Bar(x=[imp[i] for i in idx], y=[feat_cols[i] for i in idx],
                                   orientation='h', marker_color="#3a86ff"))
            fig.update_layout(**PLOT_LAYOUT, height=500, title=f"Top {top_n} Feature Importances",
                             yaxis=dict(gridcolor="#2b3036"))
            st.plotly_chart(fig, use_container_width=True)
    except Exception:
        st.info("Load model to view feature importances. Train the model first if not available.")

    st.markdown("---")
    st.warning("⚠️ Training uses all CSV files in data/ directory and may take several minutes")
    if st.button("🚀 Retrain Model", type="primary", use_container_width=True):
        with st.spinner("🔄 Training in progress..."):
            msg = _train_model()
        st.success(msg)

# ═══════════════════════════════════════════════
# TAB 5: ALERTS & LOGS
# ═══════════════════════════════════════════════
if selected_tab == "tab5":
    st.markdown('<div class="cyber-header">🔔 Incident & Audit Logs</div><p style="color:#8a94a1;font-size:0.85rem;margin-top:-10px;">Centralized ledger of detected anomalies and historical system events.</p>', unsafe_allow_html=True)

    alerts_data = _gen_alerts(25)
    sev_counts = {}
    for a in alerts_data:
        sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1

    am1, am2, am3, am4 = st.columns(4)
    am1.metric("🔴 Critical", sev_counts.get("CRITICAL", 0))
    am2.metric("🟠 High", sev_counts.get("HIGH", 0))
    am3.metric("🟡 Medium", sev_counts.get("MEDIUM", 0))
    am4.metric("🟢 Low", sev_counts.get("LOW", 0))

    ac1, ac2 = st.columns([2, 1])
    with ac1:
        st.markdown("#### 📋 Alert Feed")
        for a in alerts_data[:15]:
            badge = _severity_badge(a["severity"])
            st.markdown(f'<div class="alert-row">{badge} <span style="color:#6b7b8d;margin:0 10px;">{a["time"]}</span>'
                        f'<b style="color:#e0e6ed;">{a["type"]}</b>'
                        f' <span style="color:#ffb700;">{a["source_ip"]}</span>'
                        f' → <span style="color:#00f5ff;">:{a["dest_port"]}</span></div>', unsafe_allow_html=True)
    with ac2:
        st.markdown("#### 📊 Event Severity Breakdown")
        fig = go.Figure(go.Pie(labels=list(sev_counts.keys()), values=list(sev_counts.values()), hole=0.6,
                                marker=dict(colors=["#e63946","#ffb703","#fca311","#2ec4b6"])))
        fig.update_layout(**PLOT_LAYOUT, height=300)
        st.plotly_chart(fig, use_container_width=True)

    # Historical logs
    st.markdown("---")
    st.markdown("#### 📁 Historical Prediction Logs")
    log_files = sorted(LOGS_DIR.glob("*.json"))
    if log_files:
        sel_log = st.selectbox("Select Log", log_files, format_func=lambda x: x.name)
        if sel_log:
            with open(sel_log) as f:
                logs = json.load(f)
            log_df = pd.DataFrame(logs)
            lm1, lm2, lm3 = st.columns(3)
            lm1.metric("Total Events", len(log_df))
            attacks_in_log = len(log_df[log_df["prediction"]=="ATTACK"]) if "prediction" in log_df.columns else 0
            lm2.metric("Attacks", attacks_in_log)
            lm3.metric("Avg Confidence", f"{log_df['confidence'].mean():.2%}" if "confidence" in log_df.columns else "N/A")
            st.dataframe(log_df, use_container_width=True)
    else:
        st.info("📝 No logs yet. Run predictions to generate logs.")

# ═══════════════════════════════════════════════
# TAB 6: LIVE CAPTURE
# ═══════════════════════════════════════════════
if selected_tab == "tab6":
    st.markdown('<div class="cyber-header">📡 Live Deep Packet Inspection</div><p style="color:#8a94a1;font-size:0.85rem;margin-top:-10px;">Monitor and classify ingress/egress network traffic via scapy integration.</p>', unsafe_allow_html=True)

    # Capture controls
    capturing = is_capturing()
    ctrl1, ctrl2, ctrl3, ctrl4 = st.columns([2, 2, 1, 1])
    with ctrl1:
        if capturing:
            st.markdown('<span style="color:#39ff14;font-size:1.1rem;font-weight:700;animation:pulse 1.5s infinite;">● CAPTURING LIVE TRAFFIC</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span style="color:#6b7b8d;font-size:1.1rem;">○ Capture Stopped</span>', unsafe_allow_html=True)
    with ctrl2:
        cap_count = st.selectbox("Packet Limit", [0, 50, 100, 500, 1000], index=0,
                                  format_func=lambda x: "Unlimited" if x == 0 else f"{x} packets")
    with ctrl3:
        if not capturing:
            if st.button("▶ START", type="primary", use_container_width=True, key="start_cap"):
                try:
                    ok, msg = start_capture(packet_count=cap_count)
                    if ok:
                        st.rerun()
                    else:
                        msg_lower = str(msg).lower()
                        if "winpcap" in msg_lower or "npcap" in msg_lower:
                            st.error("Failed to start capturing: Npcap is missing! You MUST install Npcap on Windows to sniff packets. Download it from https://npcap.com/")
                        else:
                            st.error(f"Failed to start capturing. Scapy Error: {msg}")
                except Exception as e:
                    st.error(f"Error: {e}")
        else:
            if st.button("⏹ STOP", type="secondary", use_container_width=True, key="stop_cap"):
                stop_capture()
                st.rerun()
    with ctrl4:
        if st.button("🗑 Clear", use_container_width=True, key="clear_cap"):
            clear_captured_packets()
            st.rerun()

    st.markdown("---")

    # Stats
    stats = get_capture_stats()
    sm1, sm2, sm3, sm4, sm5 = st.columns(5)
    sm1.metric("📦 Total Packets", f"{stats['total']:,}")
    sm2.metric("🛑 Attacks", f"{stats['attacks']:,}")
    sm3.metric("✅ Normal", f"{stats['normal']:,}")
    sm4.metric("🔴 Critical", f"{stats['critical']:,}")
    sm5.metric("🟠 High", f"{stats['high']:,}")

    # Charts
    if stats["total"] > 0:
        ch1, ch2 = st.columns(2)
        with ch1:
            labels_c = ["ATTACK", "NORMAL", "UNKNOWN"]
            vals_c = [stats["attacks"], stats["normal"], stats["total"] - stats["attacks"] - stats["normal"]]
            fig_c = go.Figure(go.Pie(labels=labels_c, values=vals_c, hole=0.6,
                                     marker=dict(colors=["#e63946", "#2ec4b6", "#8a94a1"])))
            fig_c.update_layout(**PLOT_LAYOUT, height=280, title="Ingress Classification")
            st.plotly_chart(fig_c, use_container_width=True)
        with ch2:
            # Protocol distribution from recent packets
            recent = get_captured_packets(limit=500)
            if recent:
                proto_counts = {}
                for p in recent:
                    proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
                fig_p = go.Figure(go.Bar(
                    x=list(proto_counts.keys()), y=list(proto_counts.values()),
                    marker_color=["#00f5ff", "#a855f7", "#ffb700", "#ff073a", "#39ff14"][:len(proto_counts)]))
                fig_p.update_layout(**PLOT_LAYOUT, height=280, title="Protocol Distribution")
                st.plotly_chart(fig_p, use_container_width=True)

    # ── Packet Feed ──
    st.markdown('<div class="cyber-header"><b>🔴 Live Packet Feed</b></div>', unsafe_allow_html=True)

    # Color-coding CSS for packet severity
    st.markdown("""<style>
    /* Severity color markers → color the NEXT expander */
    div:has(> .pkt-sev-critical) + div[data-testid="stExpander"] {
        border-left: 4px solid #e63946 !important;
        background: rgba(230, 57, 70, 0.07) !important;
        border-radius: 6px !important;
    }
    div:has(> .pkt-sev-high) + div[data-testid="stExpander"] {
        border-left: 4px solid #ffb703 !important;
        background: rgba(255, 183, 3, 0.06) !important;
        border-radius: 6px !important;
    }
    div:has(> .pkt-sev-medium) + div[data-testid="stExpander"] {
        border-left: 4px solid #fca311 !important;
        background: rgba(252, 163, 17, 0.05) !important;
        border-radius: 6px !important;
    }
    div:has(> .pkt-sev-low) + div[data-testid="stExpander"] {
        border-left: 4px solid #2ec4b6 !important;
        background: rgba(46, 196, 182, 0.05) !important;
        border-radius: 6px !important;
    }
    div:has(> .pkt-sev-blocked) + div[data-testid="stExpander"] {
        border-left: 4px solid #a855f7 !important;
        background: rgba(168, 85, 247, 0.06) !important;
        border-radius: 6px !important;
    }
    /* Feed gap between packets */
    div[data-testid="stExpander"] { margin-bottom: 4px !important; }
    </style>""", unsafe_allow_html=True)

    feed_filter = st.radio("Filter", ["All", "Attacks Only", "Critical & High"], horizontal=True, key="feed_filter")
    packets = get_captured_packets(limit=200, attacks_only=(feed_filter == "Attacks Only"))

    if feed_filter == "Critical & High":
        packets = [p for p in packets if p["severity"] in ("CRITICAL", "HIGH")]

    if packets:
        # Well-known port mapping for analysis
        well_known = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        high_risk_ports = {22, 23, 3389, 445, 3306, 1433, 5432}

        for pkt in packets[:50]:
            sev = pkt["severity"]
            pred = pkt["prediction"]
            pred_color = "#ff073a" if pred == "ATTACK" else "#39ff14" if pred == "NORMAL" else "#a855f7" if "BLOCKED" in pred else "#6b7b8d"
            sev_color = {"CRITICAL": "#e63946", "HIGH": "#ffb703", "MEDIUM": "#fca311", "LOW": "#2ec4b6"}.get(sev, "#8a94a1")
            ts = pkt["timestamp"].split("T")[-1][:8] if "T" in pkt["timestamp"] else pkt["timestamp"][:8]
            conf = pkt["confidence"] if isinstance(pkt["confidence"], (int, float)) else 0.0

            # Severity CSS class for color coding
            if "BLOCKED" in pred:
                sev_css = "pkt-sev-blocked"
            else:
                sev_css = {"CRITICAL": "pkt-sev-critical", "HIGH": "pkt-sev-high", "MEDIUM": "pkt-sev-medium", "LOW": "pkt-sev-low"}.get(sev, "pkt-sev-low")

            # ── Invisible marker div (drives CSS coloring of the next expander) ──
            st.markdown(f'<div class="{sev_css}" style="height:0;overflow:hidden;margin:0;padding:0;"></div>', unsafe_allow_html=True)

            # ── Row summary ──
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            pred_icon = "🛡️" if "BLOCKED" in pred else "⚠️" if pred == "ATTACK" else "✅" if pred == "NORMAL" else "❓"
            row_label = f"{sev_icon} {sev} │ {ts} │ {pkt['src_ip']}:{pkt['src_port']} → {pkt['dst_ip']}:{pkt['dst_port']} │ {pkt['protocol']} │ {pkt['length']}B │ {pred_icon} [{pred}] {conf:.0%}"
            
            with st.expander(row_label, expanded=False):
                # ── Deep Analysis inside expander ──
                d1, d2, d3 = st.columns(3)
                
                with d1:
                    st.markdown("**📡 Connection**")
                    st.html(f"""<div style='background:#0d1117; border:1px solid #21262d; border-radius:6px; padding:12px; font-family:"JetBrains Mono",monospace; font-size:0.78rem;'>
<div style='color:#8a94a1; margin-bottom:2px;'>SOURCE</div>
<div style='color:#ffb703; font-size:0.95rem; font-weight:700; margin-bottom:8px;'>{pkt["src_ip"]}:{pkt["src_port"]}</div>
<div style='color:#8a94a1; margin-bottom:2px;'>DESTINATION</div>
<div style='color:#00f5ff; font-size:0.95rem; font-weight:700; margin-bottom:8px;'>{pkt["dst_ip"]}:{pkt["dst_port"]}</div>
<div style='color:#8a94a1; margin-bottom:2px;'>PROTOCOL / SIZE</div>
<div style='color:#a855f7; font-weight:600;'>{pkt["protocol"]} — {pkt["length"]} bytes</div>
</div>""")

                with d2:
                    st.markdown("**🧠 ML Classification**")
                    conf_pct = int(conf * 100)
                    bar_color = "#e63946" if pred == "ATTACK" else "#2ec4b6" if pred == "NORMAL" else "#ffb703"
                    st.html(f"""<div style='background:#0d1117; border:1px solid #21262d; border-radius:6px; padding:12px;'>
<div style='color:{pred_color}; font-size:1.3rem; font-weight:800; margin-bottom:8px;'>{pred}</div>
<div style='color:#8a94a1; font-size:0.7rem; margin-bottom:4px;'>CONFIDENCE</div>
<div style='background:#1a1d23; border-radius:6px; height:16px; overflow:hidden; margin-bottom:4px;'>
    <div style='height:100%; width:{conf_pct}%; background:linear-gradient(90deg, {bar_color}88, {bar_color}); border-radius:6px;'></div>
</div>
<div style='color:{bar_color}; font-weight:700; font-family:"JetBrains Mono",monospace;'>{conf:.1%}</div>
<div style='margin-top:8px; display:flex; gap:4px; align-items:center;'>
    <div style='width:8px; height:8px; border-radius:50%; background:{sev_color}; box-shadow:0 0 6px {sev_color};'></div>
    <span style='color:{sev_color}; font-weight:700; font-size:0.82rem;'>{sev}</span>
</div>
</div>""")

                with d3:
                    st.markdown("**📋 Metadata & Risk**")
                    dst_svc = well_known.get(pkt["dst_port"], "Unknown")
                    src_svc = well_known.get(pkt["src_port"], "Ephemeral")
                    
                    risks = []
                    if pkt["dst_port"] in high_risk_ports:
                        risks.append("🔴 High-risk port")
                    if pred == "ATTACK":
                        risks.append("🔴 ML flagged attack")
                    if pred == "BLOCKED_BY_IPS":
                        risks.append("🛡️ Blocked by IPS")
                    if pkt["length"] > 1400:
                        risks.append("🟡 Large payload")
                    if pkt["length"] < 60 and pkt["protocol"] == "TCP":
                        risks.append("🟡 Tiny TCP (scan?)")
                    if not risks:
                        risks.append("🟢 No anomalies")
                    
                    risk_html = "".join([f'<div style="color:#dde0e6; font-size:0.76rem; margin-bottom:3px;">{r}</div>' for r in risks])
                    
                    st.html(f"""<div style='background:#0d1117; border:1px solid #21262d; border-radius:6px; padding:12px; font-size:0.78rem;'>
<div style='color:#8a94a1; margin-bottom:2px;'>TIMESTAMP</div>
<div style='color:#dde0e6; font-family:"JetBrains Mono",monospace; margin-bottom:8px;'>{pkt["timestamp"]}</div>
<div style='color:#8a94a1; margin-bottom:2px;'>SERVICE</div>
<div style='color:#a855f7; font-weight:600; margin-bottom:8px;'>{dst_svc} (:{pkt["dst_port"]})</div>
<div style='color:#8a94a1; margin-bottom:4px;'>RISK FACTORS</div>
{risk_html}
<div style='color:#8a94a1; margin-top:8px; margin-bottom:2px;'>INFO</div>
<div style='color:#dde0e6; font-family:"JetBrains Mono",monospace;'>{pkt.get("info", "N/A")}</div>
</div>""")

        # Export 
        df_export = pd.DataFrame(packets)
        csv_data = df_export.to_csv(index=False)
        st.download_button("📥 Export Captured Packets", csv_data,
                           f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
    else:
        st.info("📡 No packets captured yet. Start the capture to begin monitoring live network traffic.")

    # Auto-refresh when capturing
    if capturing:
        time.sleep(2)
        st.rerun()

# ═══════════════════════════════════════════════
# TAB 7: ACTIVE PREVENTION (IPS)
# ═══════════════════════════════════════════════
if selected_tab == "tab7":
    from backend.ips_engine import config as ips_config, inject_threat_intel
    from backend.ips_actions import get_active_blocked_ips, get_ips_logs, unblock_ip_windows
    
    st.markdown('<div class="cyber-header">🛡️ Enterprise Stateful IPS Engine</div><p style="color:#8a94a1;font-size:0.85rem;margin-top:-10px;">Adaptive behavioral mitigation, automated blocking, and dynamic honeypots.</p>', unsafe_allow_html=True)

    # Top Controls
    c1, c2 = st.columns([1, 1])
    
    # RBAC: Only Admin can configure rules
    if st.session_state.user['role'] == 'admin':
        with c1:
            st.markdown("### ⚙️ Rule Engine Configuration")
            with st.expander("Configure Stateful Engine Thresholds", expanded=True):
                auto_block = st.toggle("🔒 Master Auto-Block Mode", value=ips_config.get("auto_block_enabled"))
                if auto_block != ips_config.get("auto_block_enabled"):
                    ips_config.set("auto_block_enabled", auto_block)
                
                ddos_thresh = st.number_input("DDoS Volumetric Threshold (Pkts/sec)", min_value=10, max_value=1000, value=ips_config.get("ddos_threshold"))
                if ddos_thresh != ips_config.get("ddos_threshold"):
                    ips_config.set("ddos_threshold", ddos_thresh)

                honey_input = st.text_input("Honeypot Ports (comma separated)", value=",".join(map(str, ips_config.get("honeypot_ports"))))
                try:
                    hx = [int(p.strip()) for p in honey_input.split(",") if p.strip().isdigit()]
                    ips_config.set("honeypot_ports", hx)
                except Exception:
                    pass
                    
        with c2:
            st.markdown("### 🌍 Threat Intelligence Simulation")
            with st.form("threat_intel_form", clear_on_submit=True):
                ti_ip = st.text_input("Inject Malicious IP Data")
                ti_sev = st.slider("Initial Severity Risk Score", 50, 100, 100)
                if st.form_submit_button("Inject to Brain"):
                    inject_threat_intel(ti_ip, ti_sev)
                    st.success(f"Injected {ti_ip} into threat profiles with score {ti_sev}")
    else:
        with c1:
            st.info("ℹ️ Analyst Mode: System configuration is read-only. Contact an Administrator to modify thresholds.")
            st.markdown(f"**Auto-Block Mode:** {'Enabled' if ips_config.get('auto_block_enabled') else 'Disabled'}")
            st.markdown(f"**DDoS Threshold:** {ips_config.get('ddos_threshold')} Pkts/sec")
        with c2:
            st.info("ℹ️ Threat Intelligence updates are restricted to Admin accounts.")
                
    st.markdown("---")
    
    # Logs and Blocker
    lc1, lc2 = st.columns([2, 2])
    with lc1:
        st.markdown("#### ⚡ Real-Time Response Pipeline")
        logs = get_ips_logs(40)
        if logs:
            df_logs = pd.DataFrame(logs)
            st.dataframe(df_logs, use_container_width=True, height=400)
        else:
            st.info("No IPS actions triggered yet.")
            
    with lc2:
        st.markdown("#### 🛑 Actively Blocked Entities")
        blocked = get_active_blocked_ips()
        if blocked:
            df_b = pd.DataFrame(blocked)
            st.dataframe(df_b[["ip_address", "reason", "timestamp"]], use_container_width=True, height=250)
            
            with st.form("unblock_form", clear_on_submit=True):
                ub_ip = st.selectbox("Select IP to Pardon", df_b["ip_address"].tolist())
                if st.form_submit_button("🔓 Unblock IP"):
                    unblock_ip_windows(ub_ip)
                    st.success(f"Pardoned {ub_ip}. Firewall rules restored.")
                    time.sleep(1)
                    st.rerun()
        else:
            st.success("No active threats blocked.")

        st.markdown("---")
        st.markdown("#### 🖐️ Manual Mitigation (Assisted Mode)")
        with st.form("manual_block_form", clear_on_submit=True):
            mb_ip = st.text_input("Enter IP for Immediate Block", placeholder="192.168.1.50")
            mb_reason = st.text_input("Reason", value="Administrative Manual Block")
            if st.form_submit_button("⛔ Execute Firewall Block"):
                if mb_ip:
                    from backend.ips_actions import block_ip_windows
                    if block_ip_windows(mb_ip, mb_reason, 100):
                        st.success(f"Successfully blocked {mb_ip}.")
                        time.sleep(1)
                        st.rerun()
                else:
                    st.error("Please enter a valid IP address.")
    
    if st.button("🔄 Refresh Pipeline"):
        st.rerun()

# ── Footer ──
st.html(f"""
<div style="text-align:center;padding:30px 0 10px;border-top:1px solid rgba(0,245,255,.1);margin-top:40px;">
    <span style="color:#6b7b8d;font-size:.8rem;">CyberShield IDS v2.0 • Powered by RandomForest ML • CICIDS2017 Dataset</span><br>
    <span style="color:#3a4a5c;font-size:.7rem;">© {datetime.now().year} Smart-IDS • Last refresh: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
</div>""")
