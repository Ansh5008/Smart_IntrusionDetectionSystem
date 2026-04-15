<p align="center">
  <img src="assets/banner.png" alt="CyberShield IDS/IPS Banner" width="100%" />
</p>

<h1 align="center">CyberShield IDS/IPS</h1>

<p align="center">
  <strong>Enterprise-Grade Intrusion Detection & Prevention System</strong><br/>
  Real-time network threat detection and active prevention powered by ML, WebSockets, and a modern SOC dashboard.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Next.js-16-black?style=for-the-badge&logo=next.js&logoColor=white" />
  <img src="https://img.shields.io/badge/TypeScript-5-3178C6?style=for-the-badge&logo=typescript&logoColor=white" />
  <img src="https://img.shields.io/badge/Supabase-Auth-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white" />
  <img src="https://img.shields.io/badge/Dataset-CICIDS2017-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

---

## Overview

**CyberShield IDS/IPS** is a production-ready, full-stack Intrusion Detection and Prevention System built for modern Security Operations Centers. It combines a **rule-based detection engine** trained on the CICIDS2017 dataset with **real-time WebSocket streaming**, an **active IPS response layer**, and a **glassmorphic Next.js SOC dashboard** — all secured by Supabase authentication.

The platform evolved from a standalone ML classifier into a complete threat detection and prevention ecosystem, capable of identifying DDoS, Port Scans, Brute Force, Data Exfiltration, and Web Attacks — and actively responding to them in real time.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CyberShield Platform                     │
│                                                                 │
│  ┌──────────────────┐        ┌──────────────────────────────┐   │
│  │  Next.js Frontend│◄──WS──►│     FastAPI Backend          │   │
│  │  (SOC Dashboard) │        │  ┌──────────┐ ┌──────────┐  │   │
│  │  - Recharts      │◄─REST─►│  │  IDS     │ │  IPS     │  │   │
│  │  - Framer Motion │        │  │ Detector │ │ Engine   │  │   │
│  │  - Supabase SSR  │        │  └──────────┘ └──────────┘  │   │
│  └──────────────────┘        │  ┌──────────────────────┐   │   │
│                              │  │  Simulation Scheduler │   │   │
│  ┌──────────────────┐        │  │  (Attack Scenarios)   │   │   │
│  │  Supabase        │        │  └──────────────────────┘   │   │
│  │  - Auth (JWT)    │        └──────────────────────────────┘   │
│  │  - User Profiles │                                           │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### 🛡️ Intrusion Detection Engine
- **Sliding-window rule engine** detecting DDoS, Port Scans, Brute Force, and Data Exfiltration
- **Confidence scoring** and dynamic severity classification (LOW → CRITICAL)
- **Composite rule support** for multi-signal attack detection (e.g., high entropy + large payload + non-standard port)
- Threat intelligence rules defined in `ids/rules.py` and evaluated per-packet in real time

### 🚫 Intrusion Prevention System
- Active response layer (`backend/ips_engine.py`) that evaluates alerts and triggers countermeasures
- Supports IP blocking, connection termination, and alert escalation
- Prevention actions logged via `backend/ips_actions.py`

### 📡 Real-Time Streaming
- **WebSocket endpoints** (`/ws/traffic`, `/ws/alerts`) push live packet and alert data to the frontend
- Attack simulation scheduler continuously generates realistic traffic with configurable attack scenarios
- Connection manager handles concurrent SOC analyst sessions

### 🖥️ SOC Dashboard (Next.js)
- **Glassmorphic UI** with Tailwind CSS, Framer Motion animations, and Recharts visualisations
- Pages: **Overview**, **Live Traffic**, **Alerts**, **Logs**, **Threat Intelligence**, **Settings**
- Responsive layout with sidebar navigation and real-time data hooks (`useWebSocket`)

### 🔐 Authentication
- Supabase-powered auth with **JWT verification** on all protected API routes
- Supports **Email/Password** and **Google OAuth**
- Server-side session management via `@supabase/ssr`

### 🤖 ML Classifier (Legacy / Batch Mode)
- **RandomForest** trained on CICIDS2017 (~99.87% accuracy)
- Batch prediction pipeline via `detection/predict.py`
- Model training tools in `src/` directory

---

## Project Structure

```
Smart-IDS/
│
├── main.py                        # Legacy Streamlit dashboard entry point
├── simulate_attacks.py            # Standalone attack simulation CLI
├── requirements.txt               # Python dependencies (legacy stack)
├── Dockerfile                     # Container definition
│
├── backend/                       # Legacy backend modules
│   ├── auth.py                    # Supabase Auth helpers
│   ├── database.py                # SQLite initialisation
│   ├── ips_engine.py              # IPS evaluation engine
│   ├── ips_actions.py             # IPS response actions
│   ├── live_capture.py            # Scapy packet capture + ML classification
│   └── supabase_config.py         # Supabase client setup
│
├── detection/                     # Inference helpers
│   ├── predict.py                 # load_artifacts + predict()
│   └── capture.py                 # Low-level capture utilities
│
├── simulation/
│   └── attack_generator.py        # AttackSimulator — synthetic traffic DataFrames
│
├── src/                           # Model training pipeline
│   ├── train.py
│   ├── preprocess.py
│   └── randomforest.py
│
├── alerts/                        # Alert processing module
├── assets/                        # Static assets (banner, screenshots)
├── data/                          # CICIDS2017 CSVs — not included, see Setup
├── models/                        # model.pkl & scaler.pkl — generated on train
├── logs/                          # Auto-created daily prediction JSON logs
│
└── ids-ips-platform/              # ✨ Full-stack IDS/IPS Platform (current)
    ├── docker-compose.yml         # Multi-service orchestration
    │
    ├── backend/                   # FastAPI backend
    │   ├── main.py                # App entry — CORS, lifespan, router registration
    │   ├── core/
    │   │   ├── config.py          # App settings
    │   │   ├── database.py        # Supabase DB client
    │   │   └── redis.py           # Redis client
    │   ├── auth/
    │   │   ├── verifier.py        # JWT verification via Supabase JWKS
    │   │   └── dependencies.py    # FastAPI auth dependencies
    │   ├── ids/
    │   │   ├── detector.py        # Sliding-window rule engine
    │   │   ├── rules.py           # ThresholdRule & CompositeRule definitions
    │   │   └── scorer.py          # Severity & confidence scoring
    │   ├── models/
    │   │   ├── packet.py          # Packet Pydantic model
    │   │   ├── alert.py           # Alert Pydantic model
    │   │   └── user.py            # User profile model
    │   ├── routers/
    │   │   ├── traffic.py         # REST: /api/traffic
    │   │   ├── alerts.py          # REST: /api/alerts
    │   │   ├── logs.py            # REST: /api/logs
    │   │   └── users.py           # REST: /api/users
    │   ├── websocket/
    │   │   ├── connection_manager.py   # Multi-client WS hub
    │   │   ├── traffic_ws.py           # WS: /ws/traffic
    │   │   └── alerts_ws.py            # WS: /ws/alerts
    │   └── simulation/
    │       ├── packet_generator.py     # Synthetic packet factory
    │       ├── attack_scenarios.py     # Attack scenario definitions
    │       └── scheduler.py            # Async simulation loop
    │
    └── frontend/                  # Next.js 16 frontend
        ├── src/
        │   ├── app/
        │   │   ├── (dashboard)/   # Protected SOC dashboard pages
        │   │   │   ├── page.tsx           # Overview
        │   │   │   ├── traffic/page.tsx   # Live Traffic
        │   │   │   ├── alerts/page.tsx    # Alerts Feed
        │   │   │   ├── logs/page.tsx      # Prediction Logs
        │   │   │   ├── intelligence/page.tsx  # Threat Intelligence
        │   │   │   └── settings/page.tsx  # Settings
        │   │   ├── login/page.tsx
        │   │   ├── signup/page.tsx
        │   │   └── auth/callback/route.ts # OAuth callback
        │   ├── components/
        │   │   └── layout/
        │   │       ├── Sidebar.tsx
        │   │       └── Topbar.tsx
        │   └── lib/
        │       ├── supabase/      # Supabase client & server helpers
        │       └── useWebSocket.ts # Real-time WS hook
        └── middleware.ts          # Route protection middleware
```

---

## Getting Started

### Prerequisites

| Requirement | Version |
|:---|:---|
| Python | 3.11+ |
| Node.js | 18+ |
| Supabase project | Free tier works |
| Redis | 7+ (optional for caching) |

---

### 1 — Clone & Install

```bash
git clone https://github.com/Ansh5008/Smart_IntrusionDetectionSystem.git
cd Smart_IntrusionDetectionSystem
```

**Backend:**
```bash
cd ids-ips-platform/backend
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install fastapi uvicorn httpx python-jose supabase
```

**Frontend:**
```bash
cd ids-ips-platform/frontend
npm install
```

---

### 2 — Configure Environment

Create `ids-ips-platform/backend/.env`:

```env
SUPABASE_URL=https://<your-project-ref>.supabase.co
SUPABASE_ANON_KEY=<your-anon-public-key>
SUPABASE_JWT_SECRET=<your-jwt-secret>
FRONTEND_URL=http://localhost:3000
REDIS_URL=redis://localhost:6379
```

Create `ids-ips-platform/frontend/.env.local`:

```env
NEXT_PUBLIC_SUPABASE_URL=https://<your-project-ref>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=<your-anon-public-key>
NEXT_PUBLIC_API_URL=http://localhost:8000
```

> **Supabase Dashboard → Settings → API** to find your URL, anon key, and JWT secret.

---

### 3 — Run the Platform

**Start the FastAPI backend:**
```bash
cd ids-ips-platform/backend
uvicorn main:app --reload --port 8000
```

**Start the Next.js frontend:**
```bash
cd ids-ips-platform/frontend
npm run dev
```

Open **[http://localhost:3000](http://localhost:3000)** in your browser.

API docs available at **[http://localhost:8000/docs](http://localhost:8000/docs)**.

---

### 4 — Docker (Full Stack)

```bash
cd ids-ips-platform
docker-compose up --build
```

---

## API Endpoints

### REST

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/` | Service health & endpoint map |
| `GET` | `/health` | Detailed health + simulation stats |
| `GET` | `/api/traffic` | Recent packet stream (paginated) |
| `GET` | `/api/alerts` | Alert feed with severity filters |
| `GET` | `/api/logs` | Historical prediction logs |
| `GET` | `/api/users` | User profile (auth required) |

### WebSocket

| Endpoint | Description |
|:---|:---|
| `ws://localhost:8000/ws/traffic` | Real-time packet stream |
| `ws://localhost:8000/ws/alerts` | Real-time alert feed |

---

## Detection Rules

| Attack Type | Rule Type | Signal |
|:---|:---|:---|
| **DDoS** | Threshold | Packet count from single IP > 100 in 10s |
| **Port Scan** | Threshold | Unique destination ports from single IP > 20 in 30s |
| **Brute Force** | Threshold | SYN packets to single port > 50 in 60s |
| **Data Exfiltration** | Composite | Payload entropy > 7.0 AND size > 40KB AND non-standard port |

---

## ML Classifier (Batch Mode)

| Property | Value |
|:---|:---|
| Algorithm | RandomForest Classifier |
| Estimators | 200 |
| Max Depth | 20 |
| Training Dataset | CICIDS2017 |
| Accuracy | ~99.87% |
| Precision | ~98.5% |
| Recall | ~97.2% |
| F1-Score | ~97.85% |

**Train the model:**
```bash
python -c "from src.train import train_from_csv; train_from_csv('data', 'Label', 'models/model.pkl', 'models/scaler.pkl')"
```

Download the [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) and place CSVs in `data/`.

---

## Tech Stack

### Backend
| Package | Purpose |
|:---|:---|
| `fastapi` | Async REST API & WebSocket server |
| `uvicorn` | ASGI server |
| `supabase` | Auth & database client |
| `python-jose` | JWT verification |
| `scikit-learn` | RandomForest classifier (batch mode) |
| `scapy` | Live packet capture |
| `pandas` / `numpy` | Data processing |

### Frontend
| Package | Purpose |
|:---|:---|
| `next` 16 | React framework (App Router) |
| `@supabase/ssr` | Server-side auth & session management |
| `recharts` | Real-time data visualisation |
| `framer-motion` | UI animations |
| `lucide-react` | Icon library |
| `tailwindcss` 4 | Utility-first styling |

---

## Authentication & Roles

| Role | Access |
|:---|:---|
| `analyst` | Default — full dashboard access |
| `admin` | Full access + user management |
| `viewer` | Read-only access |

Supported auth methods:
- ✅ Email + Password
- ✅ Google OAuth (single sign-on)
- ✅ Email-based password reset

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security research purposes only**.
Do not use attack simulation, packet capture, or IPS features on networks you do not own or have explicit written permission to test.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

<p align="center">
  CyberShield IDS/IPS &nbsp;·&nbsp; Built for cybersecurity education and research &nbsp;·&nbsp; v2.0
</p>
