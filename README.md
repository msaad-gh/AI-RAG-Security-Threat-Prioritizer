# ThreatIQ - AI-Powered Security Operations Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14.1+-black.svg)](https://nextjs.org/)

**ThreatIQ** is an intelligent security operations platform that uses AI/ML to detect, correlate, and explain security incidents.

## 🚀 Quick Start

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python -c "from utils.database import init_db; init_db()"

# Seed demo data (50 events across 5 attack scenarios)
python scripts/seed_demo_data.py

# Run backend server
python main.py
# Or: uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Backend will be available at `http://localhost:8000`  
API docs at `http://localhost:8000/docs`

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

Frontend will be available at `http://localhost:3000`

## 📋 Features

- **7-Factor Explainable Risk Scoring** - Transparent, auditable risk calculation
- **Isolation Forest Anomaly Detection** - ML-based threat detection
- **Event Correlation Engine** - Automatic incident grouping from related events
- **MITRE/CVE RAG Intelligence** - Built-in threat intelligence database
- **Structured LLM Explanations** - AI-generated incident analysis and recommendations
- **Human-in-the-Loop Actions** - Analyst review workflow with approval gates
- **Professional Dashboard** - Real-time security operations center (SOC) view

## 🏗️ Architecture

## 🏗️ Architecture
┌─────────────────────────────────────────────────────────────┐
│ ThreatIQ Platform │
├─────────────────────────────────────────────────────────────┤
│ Frontend │ Backend │ Database │
│ Next.js 14 │ FastAPI │ SQLite │
│ TypeScript │ Python 3.12 │ │
│ TailwindCSS │ SQLAlchemy │ │
├─────────────────────────────────────────────────────────────┤
│ Services: │
│ - Anomaly Detection (Isolation Forest) │
│ - Event Correlation (Time + Attribute-based) │
│ - 7-Factor Risk Scoring │
│ - RAG Threat Intelligence (MITRE/CVE) │
│ - LLM Explanations (Template-based) │
└─────────────────────────────────────────────────────────────┘


## 📊 Risk Scoring Formula

ThreatIQ uses a transparent 7-factor risk scoring model:
Overall Risk = (
threat_severity × 0.20 +
asset_criticality × 0.15 +
attack_sophistication × 0.15 +
confidence × 0.15 +
exposure × 0.15 +
temporal × 0.10 +
mitigation_gap × 0.10
) × 10


Each factor scored 0-10, overall risk 0-100.

### Risk Levels

| Score | Level | Color |
|-------|-------|-------|
| 80-100 | Critical | 🔴 Red |
| 60-79 | High | 🟠 Orange |
| 40-59 | Medium | 🟡 Yellow |
| 20-39 | Low | 🟢 Green |
| 0-19 | Info | 🔵 Blue |

## 🎯 Demo Scenarios

50 pre-seeded security events across 5 attack scenarios:

1. **Ransomware Attack** (10 events) - Complete kill chain from phishing to encryption
2. **APT Intrusion** (12 events) - Multi-day advanced persistent threat campaign
3. **Insider Threat** (10 events) - Malicious insider data exfiltration
4. **Web App Attack** (10 events) - SQL injection and web shell deployment
5. **Malware Outbreak** (8 events) - Enterprise-wide malware infection

## 🔌 API Endpoints

### Health & Config
- `GET /api/health` - Health check
- `GET /api/config` - Application configuration

### Events
- `POST /api/events` - Create security event
- `GET /api/events` - List events
- `POST /api/events/score-anomaly` - Score events for anomalies

### Incidents
- `POST /api/incidents/correlate` - Correlate events into incidents
- `GET /api/incidents` - List incidents (paginated)
- `GET /api/incidents/:id` - Get incident details
- `PUT /api/incidents/:id` - Update incident
- `POST /api/incidents/:id/actions` - Create analyst action

### Dashboard
- `GET /api/dashboard/stats` - Dashboard statistics

### RAG
- `POST /api/rag/query` - Query threat intelligence

### Demo
- `POST /api/demo/seed` - Seed demo data

## 🧪 Testing

### Backend Tests

```bash
cd backend
pytest tests/ -v
```

### Frontend

```bash
cd frontend
npm run lint
```

## 📁 Project Structure
threatiq/
├── backend/
│ ├── models/ # Database models
│ ├── api/ # Pydantic schemas
│ ├── services/ # Business logic
│ │ ├── anomaly_detection.py
│ │ ├── risk_scoring.py
│ │ ├── rag_service.py
│ │ └── llm_service.py
│ ├── utils/ # Utilities
│ ├── scripts/ # Demo data generator
│ ├── tests/ # Test suite
│ ├── main.py # FastAPI app
│ └── requirements.txt # Python dependencies
├── frontend/
│ ├── src/
│ │ ├── app/ # Next.js pages
│ │ ├── lib/ # API client
│ │ └── types/ # TypeScript types
│ └── package.json # Node dependencies
├── README.md
├── LICENSE
└── .gitignore


## 🛡️ Security Considerations

- **Input Validation** - All API inputs validated via Pydantic
- **Prompt Injection Resistance** - LLM prompts sanitized and structured
- **Graceful LLM Failure** - Template fallback when LLM unavailable
- **Human-in-the-Loop** - No autonomous blocking/deletion actions
- **No Hardcoded Secrets** - All secrets via environment variables
- **Deterministic Demo** - Pre-generated responses for reliability

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👥 Credits

**Technologies:**
- FastAPI - Modern Python web framework
- Next.js 14 - React framework with App Router
- SQLAlchemy - Python SQL toolkit
- scikit-learn - Machine learning library
- TailwindCSS - Utility-first CSS framework

**Threat Intelligence:**
- MITRE ATT&CK - Adversarial tactics and techniques
- NVD - National Vulnerability Database (CVE data)

---

**ThreatIQ** - Intelligent security operations for the modern enterprise.