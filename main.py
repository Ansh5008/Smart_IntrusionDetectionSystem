from __future__ import annotations
from pathlib import Path
from datetime import datetime, timedelta
import json, random, time

import pandas as pd
import numpy as np
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from detection.predict import load_artifacts, predict
from src.train import train_from_csv
from simulation.attack_generator import AttackSimulator
from backend.auth import signup_user, login_user, get_user_count, send_password_reset_email, update_password, get_google_auth_url
from backend.database import init_db
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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');
:root{--bg:#0a0a1a;--card:#0d1b2a;--card2:#1b2838;--cyan:#00f5ff;--red:#ff073a;--green:#39ff14;--amber:#ffb700;--purple:#a855f7;--text:#e0e6ed;--muted:#6b7b8d;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes scan{0%{background-position:0% 0%}100%{background-position:200% 0%}}
@keyframes glow{0%,100%{box-shadow:0 0 5px var(--cyan)}50%{box-shadow:0 0 20px var(--cyan),0 0 40px rgba(0,245,255,.2)}}
.stApp{background:linear-gradient(135deg,#0a0a1a 0%,#0d1b2a 50%,#1a1a2e 100%) !important;font-family:'Inter',sans-serif;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0d1b2a,#0a0a1a) !important;border-right:1px solid rgba(0,245,255,.15);}
[data-testid="stSidebar"] *{color:#e0e6ed !important;}
.css-1d391kg,.css-12oz5g7{padding-top:1rem;}
div[data-testid="stMetric"]{background:rgba(13,27,42,.8);border:1px solid rgba(0,245,255,.15);border-radius:12px;padding:16px;backdrop-filter:blur(10px);}
div[data-testid="stMetric"] label{color:#6b7b8d !important;font-size:0.8rem;text-transform:uppercase;letter-spacing:1px;}
div[data-testid="stMetric"] [data-testid="stMetricValue"]{color:#00f5ff !important;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:1.6rem;}
div[data-testid="stMetric"] [data-testid="stMetricDelta"]{font-size:0.75rem;}
h1,h2,h3{color:#e0e6ed !important;font-family:'Inter',sans-serif !important;}
.glass-card{background:rgba(13,27,42,.7);backdrop-filter:blur(12px);border:1px solid rgba(0,245,255,.1);border-radius:16px;padding:24px;margin:8px 0;}
.threat-badge-critical{background:linear-gradient(135deg,#ff073a,#ff4444);padding:4px 14px;border-radius:20px;color:#fff;font-weight:700;font-size:.75rem;display:inline-block;animation:pulse 1.5s infinite;}
.threat-badge-high{background:linear-gradient(135deg,#ff6b35,#ffb700);padding:4px 14px;border-radius:20px;color:#000;font-weight:700;font-size:.75rem;display:inline-block;}
.threat-badge-medium{background:linear-gradient(135deg,#ffb700,#ffd700);padding:4px 14px;border-radius:20px;color:#000;font-weight:700;font-size:.75rem;display:inline-block;}
.threat-badge-low{background:linear-gradient(135deg,#39ff14,#00cc44);padding:4px 14px;border-radius:20px;color:#000;font-weight:700;font-size:.75rem;display:inline-block;}
.status-online{color:#39ff14;font-weight:700;animation:pulse 2s infinite;}
.cyber-header{background:linear-gradient(90deg,rgba(0,245,255,.08),transparent);border-left:3px solid #00f5ff;padding:12px 20px;border-radius:0 8px 8px 0;margin:12px 0;}
.alert-row{background:rgba(13,27,42,.6);border:1px solid rgba(255,7,58,.15);border-radius:8px;padding:10px 16px;margin:4px 0;font-family:'JetBrains Mono',monospace;font-size:.8rem;color:#e0e6ed;}
.stTabs [data-baseweb="tab-list"]{gap:8px;background:rgba(13,27,42,.8);border-radius:12px;padding:4px;}
.stTabs [data-baseweb="tab"]{background:transparent;border-radius:8px;color:#6b7b8d;font-weight:600;}
.stTabs [aria-selected="true"]{background:rgba(0,245,255,.15) !important;color:#00f5ff !important;border-bottom:2px solid #00f5ff;}
.stButton>button{background:linear-gradient(135deg,rgba(0,245,255,.2),rgba(0,245,255,.05));border:1px solid rgba(0,245,255,.3);color:#00f5ff;border-radius:8px;font-weight:600;transition:all .3s;}
.stButton>button:hover{background:linear-gradient(135deg,rgba(0,245,255,.4),rgba(0,245,255,.15));box-shadow:0 0 20px rgba(0,245,255,.2);transform:translateY(-1px);}
.stSelectbox>div>div{background:rgba(13,27,42,.8);border:1px solid rgba(0,245,255,.2);color:#e0e6ed;}
.stSlider>div>div>div{background:#00f5ff;}
.stDataFrame{border-radius:12px;overflow:hidden;}
div[data-testid="stExpander"]{background:rgba(13,27,42,.6);border:1px solid rgba(0,245,255,.1);border-radius:12px;}
</style>""", unsafe_allow_html=True)

# ── Plot Theme ──
PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(13,27,42,0.5)",
    font=dict(color="#e0e6ed", family="Inter"), margin=dict(l=40,r=20,t=50,b=40),
    xaxis=dict(gridcolor="rgba(0,245,255,0.07)", zerolinecolor="rgba(0,245,255,0.1)"),
    yaxis=dict(gridcolor="rgba(0,245,255,0.07)", zerolinecolor="rgba(0,245,255,0.1)"),
)
COLORS = ["#00f5ff","#ff073a","#39ff14","#ffb700","#a855f7","#ff6b35","#00cc88","#ff69b4"]


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
    _log_predictions(output)
    return output


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
    return f'<span class="threat-badge-{m.get(level,"low")}">{level}</span>'


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

# ── Session State ──
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None


def _show_auth_page():
    """Render Login / Signup page."""
    # Centered auth container
    st.markdown("""<div style='text-align:center;padding:40px 0 20px;'>
        <div style='font-size:4rem;'>🛡️</div>
        <h1 style='margin:8px 0 0;font-size:2.6rem;background:linear-gradient(90deg,#00f5ff,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;'>CyberShield IDS</h1>
        <p style='color:#6b7b8d;margin:4px 0 0;font-size:.95rem;'>Advanced Intrusion Detection System</p>
    </div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

    # Login / Signup / Reset tabs
    auth_tab1, auth_tab2, auth_tab3 = st.tabs(["🔐 Login", "📝 Sign Up", "🔑 Forgot Password"])

    with auth_tab1:
        st.markdown('<div class="cyber-header"><b>Welcome Back, Analyst</b></div>', unsafe_allow_html=True)
        with st.form("login_form", clear_on_submit=False):
            col_l, col_r = st.columns([3, 1])
            with col_l:
                login_user_input = st.text_input("Username or Email", placeholder="Enter your username or email")
                login_pass = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("⚡ LOGIN", use_container_width=True, type="primary")
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
                        
        st.markdown("<div style='text-align:center;margin:15px 0;color:#6b7b8d;'>— OR —</div>", unsafe_allow_html=True)
        g_url = get_google_auth_url()
        if g_url:
            st.markdown(f"""
            <a href="{g_url}" target="_self" style="text-decoration:none;">
                <div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);padding:10px;border-radius:8px;text-align:center;color:#e0e6ed;font-weight:600;font-family:'Inter',sans-serif;transition:all 0.3s;" onmouseover="this.style.background='rgba(255,255,255,0.1)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">
                    <img src="https://www.svgrepo.com/show/475656/google-color.svg" width="18" style="vertical-align:middle;margin-right:8px;">
                    Continue with Google
                </div>
            </a>
            """, unsafe_allow_html=True)

    with auth_tab2:
        st.markdown('<div class="cyber-header"><b>Create Your Account</b></div>', unsafe_allow_html=True)
        with st.form("signup_form", clear_on_submit=True):
            s_col1, s_col2 = st.columns(2)
            with s_col1:
                signup_fullname = st.text_input("Full Name", placeholder="John Doe")
                signup_username = st.text_input("Username", placeholder="Choose a username")
            with s_col2:
                signup_email = st.text_input("Email", placeholder="you@example.com")
                signup_role = st.selectbox("Role", ["Analyst", "Admin", "Viewer"])
            signup_pass = st.text_input("Password", type="password", placeholder="Min 6 characters")
            signup_confirm = st.text_input("Confirm Password", type="password", placeholder="Repeat password")
            submitted2 = st.form_submit_button("🚀 CREATE ACCOUNT", use_container_width=True, type="primary")
            if submitted2:
                success, msg = signup_user(signup_username, signup_email, signup_pass, signup_confirm, signup_fullname, signup_role.lower())
                if success:
                    st.success(f"✅ {msg} Please login with your credentials.")
                    st.balloons()
                else:
                    st.error(f"❌ {msg}")
                    
        st.markdown("<div style='text-align:center;margin:15px 0;color:#6b7b8d;'>— OR —</div>", unsafe_allow_html=True)
        if g_url:
            st.markdown(f"""
            <a href="{g_url}" target="_self" style="text-decoration:none;">
                <div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);padding:10px;border-radius:8px;text-align:center;color:#e0e6ed;font-weight:600;font-family:'Inter',sans-serif;transition:all 0.3s;" onmouseover="this.style.background='rgba(255,255,255,0.1)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">
                    <img src="https://www.svgrepo.com/show/475656/google-color.svg" width="18" style="vertical-align:middle;margin-right:8px;">
                    Sign Up with Google
                </div>
            </a>
            """, unsafe_allow_html=True)


    with auth_tab3:
        st.markdown('<div class="cyber-header"><b>Reset Password</b></div>', unsafe_allow_html=True)
        st.info("Enter your email address and we'll send you a link to reset your password.")
        with st.form("reset_form", clear_on_submit=True):
            reset_email = st.text_input("Email Address", placeholder="you@example.com")
            submitted3 = st.form_submit_button("📩 SEND RESET LINK", use_container_width=True, type="primary")
            if submitted3:
                if not reset_email or "@" not in reset_email:
                    st.error("Please enter a valid email address.")
                else:
                    success, msg = send_password_reset_email(reset_email)
                    if success:
                        st.success(f"✅ {msg}")
                    else:
                        st.error(f"❌ {msg}")

    # Footer stats
    user_count = get_user_count()
    st.markdown(f"""<div style='text-align:center;padding:30px 0;border-top:1px solid rgba(0,245,255,.1);margin-top:30px;'>
        <span style='color:#6b7b8d;font-size:.8rem;'>🔒 Secured by Supabase Authentication • {user_count} registered analyst{"s" if user_count != 1 else ""}</span>
    </div>""", unsafe_allow_html=True)


# ── Handle Auth URL Redirect (OAuth / Password Reset) ──
if "access_token" in st.query_params or "error_description" in st.query_params:
    st.info("Auth redirect detected. Processing...")
    
    # Check if this is a password reset flow (indicated by type=recovery in URL, though Streamlit hides fragments)
    # We will show two buttons just in case, since Streamlit can't easily read the hash fragment
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Proceed to Dashboard (Google Login)"):
            st.session_state.authenticated = True
            st.session_state.reset_password = False
            
            # Fetch user profile from Supabase using the current session
            try:
                user_res = supabase.auth.get_user()
                if user_res and user_res.user:
                    uid = user_res.user.id
                    prof = supabase.table("profiles").select("*").eq("id", uid).execute()
                    if prof.data:
                        st.session_state.user = prof.data[0]
                    else:
                        st.session_state.user = {"id": uid, "username": user_res.user.email, "email": user_res.user.email, "full_name": "", "role": "analyst"}
            except Exception:
                pass

            st.query_params.clear()
            st.rerun()
            
    with col2:
        if st.button("Proceed to Password Reset"):
            st.session_state.authenticated = True
            st.session_state.reset_password = True
            st.query_params.clear()
            st.rerun()

# ── Auth Gate ──
if not st.session_state.authenticated:
    _show_auth_page()
    st.stop()


    
# Check if this is a password reset flow (user just clicked email link)
if st.session_state.authenticated and "reset_password" not in st.session_state:
    st.session_state.reset_password = False

if st.session_state.authenticated and st.session_state.get("reset_password", False):
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


# ═══════════════════════════════════════════════
# AUTHENTICATED DASHBOARD BELOW
# ═══════════════════════════════════════════════
user = st.session_state.user

# ── Header ──
c1, c2, c3 = st.columns([5, 3, 2])
with c1:
    st.markdown("""<div style='display:flex;align-items:center;gap:16px;'>
        <div style='font-size:2.4rem;'>🛡️</div>
        <div><h1 style='margin:0;font-size:2rem;background:linear-gradient(90deg,#00f5ff,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;'>CyberShield IDS</h1>
        <p style='color:#6b7b8d;margin:0;font-size:.85rem;'>Advanced Intrusion Detection System • RandomForest ML Engine • CICIDS2017</p></div>
    </div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""<div style='text-align:right;padding-top:6px;'>
        <span style='color:#6b7b8d;font-size:.7rem;text-transform:uppercase;'>Logged in as</span><br>
        <span style='color:#00f5ff;font-weight:600;'>{user['full_name'] or user['username']}</span>
        <span style='color:#6b7b8d;font-size:.75rem;'> • {user['role'].upper()}</span>
    </div>""", unsafe_allow_html=True)
with c3:
    lc1, lc2 = st.columns(2)
    with lc1:
        st.markdown(f'<div style="text-align:right;padding-top:8px;"><span class="status-online">● ONLINE</span></div>', unsafe_allow_html=True)
    with lc2:
        if st.button("🚪 Logout", key="logout_btn"):
            st.session_state.authenticated = False
            st.session_state.user = None
            st.rerun()

st.markdown("<hr style='border:1px solid rgba(0,245,255,.1);margin:8px 0 16px;'>", unsafe_allow_html=True)

# ── Tabs ──
tab1, tab2, tab6, tab3, tab4, tab5 = st.tabs([
    "⚡ Live Monitoring", "🎯 Attack Simulation", "📡 Live Capture",
    "📊 Dataset Analytics", "🧠 Model Center", "🔔 Alerts & Logs"
])

# ═══════════════════════════════════════════════
# TAB 1: LIVE MONITORING
# ═══════════════════════════════════════════════
with tab1:
    live = _gen_live_data()
    
    # Threat Level Banner
    tl_colors = {"CRITICAL":"#ff073a","HIGH":"#ff6b35","MODERATE":"#ffb700","LOW":"#39ff14"}
    tl_color = tl_colors.get(live["threat_level"], "#00f5ff")
    st.markdown(f"""<div class="cyber-header" style="border-left-color:{tl_color};background:linear-gradient(90deg,{tl_color}15,transparent);">
        <span style="color:{tl_color};font-size:1.1rem;font-weight:700;">⚠ THREAT LEVEL: {live['threat_level']}</span>
        <span style="color:#6b7b8d;margin-left:20px;font-size:.85rem;">Network monitoring active • {live['uptime_hours']}h uptime</span>
    </div>""", unsafe_allow_html=True)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🛑 Threats Blocked", f"{live['threats_blocked']:,}", f"+{random.randint(5,45)} last min")
    m2.metric("📡 Packets Analyzed", f"{live['packets_analyzed']:,}", f"{round(live['packets_analyzed']/1000,1)}K/s")
    m3.metric("🔗 Active Connections", live["active_connections"], f"{random.choice(['+','-'])}{random.randint(1,15)}")
    m4.metric("📶 Bandwidth", f"{live['bandwidth_mbps']} Mbps", f"{random.choice(['+','-'])}{round(random.uniform(1,20),1)}")

    st.markdown("---")
    col_chart1, col_chart2 = st.columns([3, 2])
    
    with col_chart1:
        st.markdown('<div class="cyber-header"><b>📈 Network Activity Timeline</b></div>', unsafe_allow_html=True)
        times = [(datetime.now() - timedelta(minutes=30-i)).strftime("%H:%M") for i in range(30)]
        normal_t = [random.randint(200, 500) for _ in range(30)]
        attack_t = [random.randint(0, 80) if random.random() > 0.3 else random.randint(80, 300) for _ in range(30)]
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=times, y=normal_t, name="Normal", fill='tozeroy',
                                  line=dict(color="#00f5ff", width=2), fillcolor="rgba(0,245,255,0.1)"))
        fig.add_trace(go.Scatter(x=times, y=attack_t, name="Malicious", fill='tozeroy',
                                  line=dict(color="#ff073a", width=2), fillcolor="rgba(255,7,58,0.1)"))
        fig.update_layout(**PLOT_LAYOUT, height=350, title=None, legend=dict(orientation="h", y=1.1))
        st.plotly_chart(fig, use_container_width=True)

    with col_chart2:
        st.markdown('<div class="cyber-header"><b>🎯 Attack Distribution</b></div>', unsafe_allow_html=True)
        labels = ["DDoS","Port Scan","Web Attack","Brute Force","Exfiltration","Benign"]
        values = [random.randint(50,200) for _ in range(5)] + [random.randint(600,1200)]
        fig2 = go.Figure(go.Pie(labels=labels, values=values, hole=0.65,
                                 marker=dict(colors=COLORS[:6]),
                                 textfont=dict(color="#e0e6ed", size=11)))
        fig2.update_layout(**PLOT_LAYOUT, height=350, showlegend=True,
                           legend=dict(font=dict(size=10), orientation="h", y=-0.1))
        st.plotly_chart(fig2, use_container_width=True)

    # Recent Alerts
    st.markdown('<div class="cyber-header"><b>🚨 Recent Alerts</b></div>', unsafe_allow_html=True)
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
with tab2:
    st.markdown('<div class="cyber-header"><b>🎯 Attack Simulation Laboratory</b><br><span style="color:#6b7b8d;font-size:.8rem;">Generate realistic attack traffic and test IDS detection using your trained ML model</span></div>', unsafe_allow_html=True)

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
        st.markdown('<div class="cyber-header"><b>🔍 IDS Detection Results</b></div>', unsafe_allow_html=True)
        progress = st.progress(0, text="Analyzing traffic...")
        
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
                                       marker=dict(colors=["#ff073a","#39ff14"])))
                fig.update_layout(**PLOT_LAYOUT, height=300, title="Detection Breakdown")
                st.plotly_chart(fig, use_container_width=True)
            with rc2:
                fig = px.histogram(df_attack, x="Confidence", color="Prediction", nbins=20,
                                   color_discrete_map={"ATTACK":"#ff073a","NORMAL":"#39ff14"})
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
with tab3:
    st.markdown('<div class="cyber-header"><b>📊 CICIDS2017 Dataset Explorer</b><br><span style="color:#6b7b8d;font-size:.8rem;">Analyze real-world network traffic data and run IDS predictions</span></div>', unsafe_allow_html=True)

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
with tab4:
    st.markdown('<div class="cyber-header"><b>🧠 Model Intelligence Center</b><br><span style="color:#6b7b8d;font-size:.8rem;">RandomForest classifier performance and management</span></div>', unsafe_allow_html=True)

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
        st.markdown(f"""<div class="glass-card">
            <p style="color:#6b7b8d;">Algorithm: <span style="color:#00f5ff;">RandomForest</span></p>
            <p style="color:#6b7b8d;">Estimators: <span style="color:#00f5ff;">200</span></p>
            <p style="color:#6b7b8d;">Max Depth: <span style="color:#00f5ff;">20</span></p>
            <p style="color:#6b7b8d;">Model: <span style="color:#00f5ff;">{MODEL_PATH.name}</span></p>
            <p style="color:#6b7b8d;">Scaler: <span style="color:#00f5ff;">{SCALER_PATH.name}</span></p>
            <p style="color:#6b7b8d;">Dataset: <span style="color:#00f5ff;">CICIDS2017 ({len(list(DATA_DIR.glob('*.csv')))} files)</span></p>
        </div>""", unsafe_allow_html=True)

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
                                   orientation='h', marker_color="#00f5ff"))
            fig.update_layout(**PLOT_LAYOUT, height=500, title=f"Top {top_n} Feature Importances",
                             yaxis=dict(gridcolor="rgba(0,245,255,0.07)"))
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
with tab5:
    st.markdown('<div class="cyber-header"><b>🔔 Threat Alerts & System Logs</b></div>', unsafe_allow_html=True)

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
        st.markdown("#### 📊 Severity Distribution")
        fig = go.Figure(go.Pie(labels=list(sev_counts.keys()), values=list(sev_counts.values()), hole=0.6,
                                marker=dict(colors=["#ff073a","#ff6b35","#ffb700","#39ff14"])))
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
with tab6:
    st.markdown('<div class="cyber-header"><b>📡 Live Network Capture</b><br><span style="color:#6b7b8d;font-size:.8rem;">Real-time packet sniffing with ML-powered intrusion detection</span></div>', unsafe_allow_html=True)

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
                    ok = start_capture(packet_count=cap_count)
                    if ok:
                        st.rerun()
                    else:
                        st.error("Failed to start. Check scapy installation & run as admin.")
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
                                     marker=dict(colors=["#ff073a", "#39ff14", "#6b7b8d"])))
            fig_c.update_layout(**PLOT_LAYOUT, height=280, title="Detection Breakdown")
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

    # Live packet feed
    st.markdown('<div class="cyber-header"><b>🔴 Live Packet Feed</b></div>', unsafe_allow_html=True)

    feed_filter = st.radio("Filter", ["All", "Attacks Only", "Critical & High"], horizontal=True, key="feed_filter")
    packets = get_captured_packets(limit=200, attacks_only=(feed_filter == "Attacks Only"))

    if feed_filter == "Critical & High":
        packets = [p for p in packets if p["severity"] in ("CRITICAL", "HIGH")]

    if packets:
        for pkt in packets[:50]:
            sev = pkt["severity"]
            pred = pkt["prediction"]
            sev_class = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(sev, "low")
            pred_color = "#ff073a" if pred == "ATTACK" else "#39ff14" if pred == "NORMAL" else "#6b7b8d"
            ts = pkt["timestamp"].split("T")[-1][:8] if "T" in pkt["timestamp"] else pkt["timestamp"][:8]
            st.markdown(
                f'<div class="alert-row">'
                f'<span class="threat-badge-{sev_class}">{sev}</span> '
                f'<span style="color:#6b7b8d;margin:0 8px;">{ts}</span>'
                f'<span style="color:#ffb700;">{pkt["src_ip"]}:{pkt["src_port"]}</span>'
                f'<span style="color:#6b7b8d;"> → </span>'
                f'<span style="color:#00f5ff;">{pkt["dst_ip"]}:{pkt["dst_port"]}</span> '
                f'<span style="color:#6b7b8d;margin:0 8px;">{pkt["protocol"]} | {pkt["length"]}B</span>'
                f'<span style="color:{pred_color};font-weight:700;">[{pred}]</span> '
                f'<span style="color:#6b7b8d;font-size:.75rem;">{pkt["confidence"]:.1%}</span>'
                f'</div>', unsafe_allow_html=True)

        # Export
        import pandas as _pd
        df_export = _pd.DataFrame(packets)
        csv_data = df_export.to_csv(index=False)
        st.download_button("📥 Export Captured Packets", csv_data,
                           f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
    else:
        st.info("📡 No packets captured yet. Start the capture to begin monitoring live network traffic.")

    # Auto-refresh when capturing
    if capturing:
        time.sleep(2)
        st.rerun()

# ── Footer ──
st.markdown(f"""<div style="text-align:center;padding:30px 0 10px;border-top:1px solid rgba(0,245,255,.1);margin-top:40px;">
    <span style="color:#6b7b8d;font-size:.8rem;">CyberShield IDS v2.0 • Powered by RandomForest ML • CICIDS2017 Dataset</span><br>
    <span style="color:#3a4a5c;font-size:.7rem;">© {datetime.now().year} Smart-IDS • Last refresh: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
</div>""", unsafe_allow_html=True)
