# Security Log Analyzer

A high-performance, fully offline, hybrid security event detection engine built in Python.

## The Judge Pitch

**Security Log Analyzer** is a robust incident detection pipeline that fuses deterministic rule engines with machine-learning behavioral baselines. Unlike traditional SIEMs that either drown analysts in raw alerts or rely entirely on black-box ML, this system guarantees that **every alert is backed by explicit, human-readable evidence**. The core pipeline runs entirely offline, meaning zero data exfiltration risk, while the optional Phase 8 layers demonstrate cutting-edge log compression (Drain3) and generative AI (LLM) enrichment. 

> 📖 **Full System Architecture & Workflow Specification:** See [ARCHITECTURE_AND_WORKFLOW.md](ARCHITECTURE_AND_WORKFLOW.md) for full module diagrams, detection rule mathematics, per-user ML baseline designs, correlation scoring formulas, and API reference.

---

## 🚀 Quick Start (First-Time Users)

### 1. Clone & Setup Environment
```bash
git clone <repository_url>
cd security-log-analyzer

# Create a virtual environment and activate it
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install markdown weasyprint reportlab drain3 openai python-dotenv
```

### 2. Configure Environment (Optional LLM Integration)
Copy the example environment file and add your OpenAI key if you want to use the AI Narrative feature.
```bash
cp .env.example .env
# Open .env and add your OPENAI_API_KEY
```

### 3. Run the Backend
The backend utilizes FastAPI and SQLite (auto-created).
```bash
python -m uvicorn app.main:app --reload
```

### 4. Run the E2E Demo Script
In a new terminal window, run the full pipeline demo script. This will generate synthetic logs, upload them, trigger the rule/ML engines, and generate the final correlation incident reports.
```bash
# On Mac/Linux (Git Bash)
bash tests/demo_script.sh

# On Windows (PowerShell)
.\tests\demo_script.ps1
```

### 5. Access the Dashboard & Docs
- **Interactive Dashboard:** [http://localhost:8000/](http://localhost:8000/)
- **Swagger API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check:** [http://localhost:8000/health](http://localhost:8000/health)

---

## 🛠 Features Breakdown

- **Phase 1 (Ingestion):** Stream-safe CSV parsing using `pandas` chunks.
- **Phase 2 (Deterministic Rules):** 7 core rules (Brute Force, PrivEsc, Recon, Off-Hours, Mass Deletion, Multiple IPs, Suspicious IP).
- **Phase 3 (ML Anomaly):** Rolling Entity Baselines & Isolation Forest modeling.
- **Phase 4 (Correlation):** Fuses ML and Rule alerts into scored incidents over 30-minute rolling windows.
- **Phase 5 (Remediation):** Deterministic priority action mapping with full transactional Audit Logging.
- **Phase 6 (UI):** Server-rendered Jinja2 Dashboard with Chart.js and Vanilla JS drill-downs.
- **Phase 7 (Reporting):** Auto-translates raw algorithm math into plain English Executive Summaries (Markdown & PDF).
- **Phase 8 (LLM Narrative):** Compresses logs via `drain3` and generates Non-Technical LLM summaries.
