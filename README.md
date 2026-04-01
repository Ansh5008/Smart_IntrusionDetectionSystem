<p align="center">
  <img src="assets/banner.png" alt="CyberShield IDS Banner" width="100%" />
</p>

<h1 align="center">CyberShield IDS</h1>

<p align="center">
  <strong>Smart Intrusion Detection System</strong><br/>
  ML-powered network security monitoring with real-time packet capture and a premium Streamlit dashboard.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Streamlit-1.28+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" />
  <img src="https://img.shields.io/badge/Scikit--Learn-RandomForest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" />
  <img src="https://img.shields.io/badge/Supabase-Auth-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white" />
  <img src="https://img.shields.io/badge/Dataset-CICIDS2017-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

---

## Overview

**CyberShield IDS** is a full-featured Intrusion Detection System that combines a **RandomForest ML classifier** trained on the CICIDS2017 network traffic dataset with a live, interactive dashboard. It can classify network traffic in real time, simulate attack scenarios for testing, and provides a secure multi-role web interface backed by **Supabase Authentication**.

---

## Features

| Module | Description |
|:---|:---|
| ⚡ **Live Monitoring** | Real-time threat level banner, network activity timelines, and rolling attack distribution charts |
| 📡 **Live Packet Capture** | Scapy-based packet sniffer that classifies each packet using the trained ML model |
| 🎯 **Attack Simulation** | Synthesize DDoS, Port Scan, Brute Force, Web Attack, Data Exfiltration, or Mixed traffic |
| 📊 **Dataset Analytics** | Load and visualise CICIDS2017 CSV files, then run batch IDS predictions |
| 🧠 **Model Center** | Train / retrain the RandomForest model, view feature importances and performance metrics |
| 🔔 **Alerts & Logs** | Filterable alert feed by severity and historical per-day JSON prediction log viewer |
| 🔐 **Authentication** | Supabase-powered email/password sign-up, Google OAuth, and password reset |

---

## Project Structure

```
Smart-IDS/
├── main.py                   # Streamlit dashboard entry point
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container definition
├── simulate_attacks.py       # Standalone attack simulation CLI
├── stress_test.py            # Load / stress testing utilities
│
├── backend/
│   ├── auth.py               # Supabase Auth (sign-up, login, OAuth, password reset)
│   ├── database.py           # SQLite initialisation
│   ├── live_capture.py       # Packet capture thread + ML classification
│   └── supabase_config.py    # Supabase client setup
│
├── detection/
│   ├── predict.py            # Inference helpers (load_artifacts, predict)
│   └── capture.py            # Low-level capture utilities
│
├── simulation/
│   └── attack_generator.py   # AttackSimulator — generates synthetic traffic DataFrames
│
├── src/
│   └── train.py              # Model training pipeline
│
├── alerts/                   # Alert processing module
├── assets/                   # Static assets (banner, screenshots)
├── data/                     # CICIDS2017 CSV files (not included — see Setup)
├── models/                   # model.pkl & scaler.pkl (generated on first train)
└── logs/                     # Auto-created daily prediction JSON logs
```

---

## Getting Started

### Prerequisites

- Python **3.11+**
- A [Supabase](https://supabase.com) project (free tier works)
- CICIDS2017 dataset CSVs (see [Dataset](#dataset))
- Administrator / root privileges for live packet capture (Scapy)

---

### 1 — Clone & Install

```bash
git clone https://github.com/<your-username>/Smart-IDS.git
cd Smart-IDS

python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

---

### 2 — Configure Supabase

Create a `.env` file in the project root:

```env
SUPABASE_URL=https://<your-project-ref>.supabase.co
SUPABASE_KEY=<your-anon-public-key>
```

> **Supabase Dashboard → Settings → API** to find your URL and anon key.

Apply the following migration in the **Supabase SQL Editor** to create the profiles table:

```sql
create table public.profiles (
  id        uuid primary key references auth.users(id) on delete cascade,
  username  text unique not null,
  email     text unique not null,
  full_name text,
  role      text default 'analyst'
);
```

---

### 3 — Add the Dataset

Download the [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) CSV files and place them in the `data/` directory:

```
data/
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
└── ...
```

---

### 4 — Train the Model

Launch the app and navigate to **🧠 Model Center → Retrain Model**, or run training headlessly:

```bash
python -c "from src.train import train_from_csv; train_from_csv('data', 'Label', 'models/model.pkl', 'models/scaler.pkl')"
```

This produces `models/model.pkl` and `models/scaler.pkl`.

---

### 5 — Run the Dashboard

```bash
streamlit run main.py
```

Open **[http://localhost:8501](http://localhost:8501)** in your browser.

---

## Docker

```bash
# Build
docker build -t cybershield-ids .

# Run
docker run -p 8501:8501 \
  -e SUPABASE_URL=<url> \
  -e SUPABASE_KEY=<key> \
  cybershield-ids \
  streamlit run main.py --server.port 8501 --server.address 0.0.0.0
```

---

## ML Model

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

---

## Authentication & Roles

| Role | Access |
|:---|:---|
| `analyst` | Default role — full dashboard access |
| `admin` | Full access + user management |
| `viewer` | Read-only access |

Supported auth methods:
- ✅ Email + Password
- ✅ Google OAuth (single sign-on)
- ✅ Email-based password reset

---

## Dependencies

| Package | Version | Purpose |
|:---|:---|:---|
| `streamlit` | ≥ 1.28 | Dashboard UI |
| `plotly` | ≥ 5.17 | Interactive charts |
| `scikit-learn` | latest | RandomForest classifier |
| `pandas` / `numpy` | latest | Data processing |
| `scapy` | latest | Live packet capture |
| `supabase` | ≥ 2.0 | Auth & database |
| `joblib` | latest | Model serialisation |
| `scipy` | latest | Numerical utilities |

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security research purposes only**.  
Do not use attack simulation or live packet capture on networks you do not own or have explicit written permission to test.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

<p align="center">
  Made for cybersecurity education &nbsp;|&nbsp; CyberShield IDS v2.0
</p>
