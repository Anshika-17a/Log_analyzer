# 🛡️ Security Log Analyzer

> An enterprise-grade, explainable hybrid security intelligence platform — combining deterministic Sigma-style rule engines, per-user Machine Learning behavioral anomaly detection, multi-stage incident correlation, automated remediation playbooks, interactive attack blast-radius graph visualization, and Generative AI cyber kill-chain story reconstruction.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Architecture Overview](#-architecture-overview)
- [Project Structure](#-project-structure)
- [Setup & Installation](#-setup--installation)
- [Running the Application](#-running-the-application)
- [One-Click Live Demo Mode](#-one-click-live-demo-mode)
- [API Reference](#-api-reference)
- [Running Tests](#-running-tests)
- [Environment Variables](#-environment-variables)
- [Database Schema](#-database-schema)

---

## ✨ Features

### Core Detection Engine
- **7 Deterministic Security Rules** — Brute Force, Privilege Escalation, Impossible Travel (geolocation), Off-Hours Access, Reconnaissance Spray, Bulk Data Exfiltration, Dormant Account Reactivation
- **Per-User ML Behavioral Baseline** — `IsolationForest` trained on a 9-dimensional feature vector per user (hour-of-day entropy, IP velocity, event rate, etc.)
- **Hybrid Alert Fusion** — Rule-based + ML alerts merged, deduplicated, and correlated into multi-stage incident tickets

### Incident Management
- **Composite Risk Scoring** — Dynamic 0–100 score weighting rule severity, ML anomaly deviation, MITRE tactic coverage, and lateral movement signals
- **30-Minute Rolling Correlation Window** — Groups related alerts per user into coherent incident timelines
- **Status Lifecycle** — `open → reviewing → resolved → false_positive` with full transactional audit logging

### Visualization & Reporting
- **Interactive Attack Blast Radius Graph** — Force-directed SVG graph linking users, IPs, security rules, MITRE ATT&CK techniques, and remediation actions
- **MITRE ATT&CK Enterprise Heatmap Matrix** — Live heat-map across 8 tactics and 40+ techniques, colour-coded by incident frequency
- **Chronological Cyber Kill-Chain Story** — 14-stage kill-chain reconstruction with Gemini AI narrative and deterministic fallback
- **PDF & Markdown Reports** — Per-incident dossiers and organization-wide posture summaries

### Live Demo Mode (Phase 13)
- **One-Click Scenario Presets** — Instantly inject authentic raw telemetry for APT29, Insider Threat, or Clean Baseline scenarios
- **Animated Live Terminal Ticker** — Streams log records in real time with colour-coded threat tags
- **Auto-Open Attack Graph** — Automatically opens the top-scored incident's blast radius graph after simulation

---

## 🛠️ Tech Stack

### Backend
| Component | Technology |
|-----------|-----------|
| Web Framework | [FastAPI](https://fastapi.tiangolo.com/) |
| ASGI Server | [Uvicorn](https://www.uvicorn.org/) |
| ORM | [SQLAlchemy](https://www.sqlalchemy.org/) |
| Database | SQLite (file: `logs.db`) |
| Data Processing | [Pandas](https://pandas.pydata.org/) |
| ML Engine | [scikit-learn](https://scikit-learn.org/) — `IsolationForest` |
| Log Clustering | [Drain3](https://github.com/logpai/drain3) |
| PDF Generation | [ReportLab](https://www.reportlab.com/) / [WeasyPrint](https://weasyprint.org/) |
| AI Narrative | [Google Gemini API](https://ai.google.dev/) (`gemini-flash-latest`) |
| Config | [python-dotenv](https://pypi.org/project/python-dotenv/) |

### Frontend
| Component | Technology |
|-----------|-----------|
| Templating | Jinja2 (server-rendered) |
| Charts | [Chart.js](https://www.chartjs.org/) |
| Attack Graph | Vanilla SVG + Force-Directed JS |
| Styling | Vanilla CSS (dark theme, glassmorphism) |
| Fonts | [Inter](https://fonts.google.com/specimen/Inter) via Google Fonts |

### DevOps & Testing
| Component | Technology |
|-----------|-----------|
| Testing | [pytest](https://pytest.org/) + custom integration test scripts |
| API Docs | Auto-generated Swagger UI + ReDoc |
| Version Control | Git |

---

## 🏗️ Architecture Overview

```
Raw Logs (CSV / JSON / JSONL / Syslog)
        │
        ▼
┌─────────────────────┐
│  Phase 1: Ingestion │  ← Multi-format parser, dedup hash, normalization
└──────────┬──────────┘
           │
    ┌──────┴──────┐
    ▼             ▼
┌───────────┐  ┌──────────────────────┐
│  7 Sigma  │  │  Per-User ML         │
│  Rules    │  │  IsolationForest     │
│  (Phase 2)│  │  Baseline (Phase 3)  │
└─────┬─────┘  └──────────┬───────────┘
      │                   │
      └─────────┬─────────┘
                ▼
     ┌─────────────────────┐
     │ Phase 4: Correlation │  ← 30-min rolling window, per-user grouping
     └──────────┬──────────┘
                ▼
     ┌─────────────────────┐
     │ Phase 5: Risk Score  │  ← Composite 0–100 dynamic score
     └──────────┬──────────┘
                ▼
     ┌─────────────────────┐
     │ Phase 6: Remediation │  ← Automated action playbooks
     └──────────┬──────────┘
                ▼
     ┌──────────────────────────────────────────┐
     │            SOC Dashboard                  │
     │  Incident Queue │ Attack Graph │ MITRE    │
     │  Kill-Chain Story │ PDF Reports │ AI Chat │
     └──────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
security-log-analyzer/
│
├── app/
│   ├── main.py                        # FastAPI app, all route handlers
│   ├── simulation.py                  # One-click live attack scenario generator
│   │
│   ├── ingestion/
│   │   └── parser.py                  # Multi-format log parser & normalizer
│   │
│   ├── detection/
│   │   ├── rules.py                   # 7 deterministic Sigma-style rules
│   │   ├── baseline.py                # Per-user entity baseline computation
│   │   ├── ml_anomaly.py              # IsolationForest ML anomaly detection
│   │   └── mitre_mapping.py           # Rule → MITRE ATT&CK technique mapping
│   │
│   ├── correlation/
│   │   ├── grouping.py                # Alert → Incident correlation engine
│   │   ├── scoring.py                 # Composite risk scoring engine
│   │   └── graph_builder.py           # Attack blast-radius graph builder
│   │
│   ├── reporting/
│   │   ├── report_generator.py        # PDF & Markdown report generation
│   │   ├── narrative.py               # Drain3 clustering + Gemini AI narrative
│   │   └── story_reconstruction.py    # 14-stage kill-chain story builder
│   │
│   ├── models/
│   │   ├── db.py                      # SQLAlchemy engine & session factory
│   │   ├── schema.py                  # ORM models (Log, Alert, Incident, etc.)
│   │   └── api.py                     # Pydantic request/response schemas
│   │
│   ├── remediation/                   # Remediation action mapping
│   │
│   └── dashboard/
│       └── templates/
│           └── dashboard.html         # Full SOC dashboard (single-page)
│
├── data/
│   ├── gen_synthetic_logs.py          # Synthetic log data generator
│   ├── sample_logs.csv                # 500-row sample dataset
│   └── sample_10k.csv                 # 10,000-row performance dataset
│
├── tests/
│   └── test_ml_anomaly.py             # ML baseline unit tests
│
├── test_phase12_simulation.py         # Simulation endpoint integration tests
├── test_phase5.py                     # Incident & audit log integration tests
│
├── .env.example                       # Environment variable template
├── requirements.txt                   # Python dependencies
├── pytest.ini                         # Pytest configuration
├── logs.db                            # SQLite database (auto-created)
└── ARCHITECTURE_AND_WORKFLOW.md       # Full system documentation
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python **3.9+**
- pip
- Git

### 1. Clone the repository

```bash
git clone https://github.com/Anshika-17a/Log_analyzer.git
cd Log_analyzer
```

### 2. Create and activate a virtual environment

```bash
# Create virtual environment
python -m venv venv

# Activate — Windows (PowerShell)
.\venv\Scripts\activate

# Activate — macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing any package, install manually:

```bash
pip install fastapi uvicorn sqlalchemy pandas numpy scikit-learn drain3 google-genai reportlab weasyprint python-dotenv jinja2
```

### 4. Configure environment variables

```bash
# Copy the example file
cp .env.example .env
```

Open `.env` and fill in your values:

```env
DATABASE_URL=sqlite:///./logs.db
ENABLE_DRAIN3=true
ENABLE_LLM_NARRATIVE=true
GEMINI_API_KEY=your_gemini_api_key_here
```

> **Note:** `GEMINI_API_KEY` is only required for the AI Narrative feature (Tab 1 of the incident modal). All other features work fully offline without any API key.

---

## 🚀 Running the Application

```bash
# Start the development server with hot-reload
python -m uvicorn app.main:app --reload
```

The server starts on `http://localhost:8000` by default.

| URL | Description |
|-----|-------------|
| `http://localhost:8000/` | SOC Dashboard (main UI) |
| `http://localhost:8000/docs` | Interactive Swagger API docs |
| `http://localhost:8000/redoc` | ReDoc API docs |
| `http://localhost:8000/health` | Health check endpoint |

### Uploading your first log file

1. Open `http://localhost:8000/`
2. Click **Choose File** and select `data/sample_logs.csv`
3. Click **▶ Run Full Analysis**
4. Click any incident row to open the detail modal

**Supported log formats:** `.csv`, `.json`, `.jsonl`, `.log`, `.syslog`, `.ndjson`, `.txt`

---

## ⚡ One-Click Live Demo Mode

No log file needed. At the top of the dashboard, three preset scenario buttons inject authentic simulated telemetry directly through the full detection pipeline:

| Button | Scenario | What it demonstrates |
|--------|----------|---------------------|
| 🔴 **Simulate APT29 State-Sponsored Breach** | Multi-stage kill chain | Brute force → Impossible Travel (Moscow IP) → Root PrivEsc → Recon spray → 110-file data dump |
| 🟠 **Simulate Insider Data Exfiltration** | Behavioral anomaly | Normal dev baseline → 02:45 AM off-hours login → 115 confidential files exported |
| 🟢 **Simulate Normal Business Traffic** | Clean baseline | Normal working-hours CRM/portal traffic, zero rule violations |

**What happens when you click:**
1. Raw telemetry is built in-memory and injected through the CSV parser
2. A live animated terminal ticker streams each log record with colour-coded threat tags
3. 7 Sigma rules + IsolationForest ML baseline runs on all ingested logs
4. Incidents are correlated and scored
5. The top-scored incident's **Attack Blast Radius Graph** auto-opens

---

## 📡 API Reference

### Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/logs/upload` | Upload a log file (CSV/JSON/JSONL/syslog) |
| `GET` | `/api/logs` | Paginated list of ingested log records |

### Detection
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/alerts` | Run all rules + ML detection, return generated alerts |

### Incidents
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/incidents` | Correlate alerts into incidents, return ranked list |
| `GET` | `/api/incidents/{id}` | Detailed view of a single incident |
| `PUT` | `/api/incidents/{id}/status` | Update incident status (`open`, `reviewing`, `resolved`, `false_positive`) |
| `GET` | `/api/incidents/{id}/graph` | Attack blast-radius graph (nodes + edges JSON) |
| `GET` | `/api/incidents/{id}/story` | Chronological kill-chain story reconstruction |
| `GET` | `/api/incidents/{id}/narrative` | Gemini AI executive narrative |

### MITRE ATT&CK
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/mitre/matrix` | Technique frequency heatmap across all incidents |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/reports/{id}?format=md\|pdf` | Download per-incident report |
| `GET` | `/api/reports/summary?format=md\|pdf` | Download org-wide posture report |

### Simulation
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/simulate/{scenario}` | Inject simulated scenario (`apt29`, `insider`, `benign`) |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/system/reset` | Clear all logs, alerts, incidents, and baselines |
| `GET` | `/health` | Health check |

---

## 🧪 Running Tests

```bash
# Run the ML anomaly unit tests (pytest)
.\venv\Scripts\pytest.exe

# Run the simulation endpoint integration test
$env:PYTHONIOENCODING="utf-8"; .\venv\Scripts\python.exe test_phase12_simulation.py

# Run the incident & audit log integration test
.\venv\Scripts\python.exe test_phase5.py
```

---

## 🔐 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | No | `sqlite:///./logs.db` | SQLAlchemy database connection string |
| `ENABLE_DRAIN3` | No | `true` | Enable Drain3 log template clustering |
| `ENABLE_LLM_NARRATIVE` | No | `true` | Enable Gemini AI narrative generation |
| `GEMINI_API_KEY` | No* | — | Google Gemini API key for AI narratives |

> *Required only for the AI Narrative feature. Everything else is fully offline.

---

## 🗄️ Database Schema

The SQLite database (`logs.db`) is auto-created on first startup via `Base.metadata.create_all()`.

| Table | Description |
|-------|-------------|
| `log` | Raw ingested log records |
| `alert` | Generated alerts (rule-based + ML) |
| `incident` | Correlated multi-stage incidents with risk scores |
| `incident_action` | Automated remediation action playbook items |
| `entity_baseline` | Per-user ML behavioral baseline statistics |
| `audit_log` | Transactional log of all incident status changes |

### Resetting the database

If you update ORM models or want a clean slate:

```bash
# Option 1 — Delete the database file
del logs.db          # Windows
rm logs.db           # macOS / Linux

# Option 2 — Use the API endpoint
curl -X POST http://localhost:8000/api/system/reset
```

Then restart the server — tables are recreated automatically.

---

## 📖 Full Documentation

See [`ARCHITECTURE_AND_WORKFLOW.md`](ARCHITECTURE_AND_WORKFLOW.md) for:
- Complete 13-phase pipeline breakdown with data flow diagrams
- Detection rule mathematics and thresholds
- Per-user ML baseline feature vector specification
- Correlation scoring formula
- Full API schema reference
- MITRE ATT&CK technique mappings
