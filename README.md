# 🕸️ GAGMA — Graph-Augmented GenAI Malware Analyst

> Automated Android APK malware analysis powered by **Neo4j knowledge graphs** and **multi-agent GenAI**.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![Neo4j](https://img.shields.io/badge/Neo4j-Graph%20DB-blue)
![Gemini](https://img.shields.io/badge/Gemini-AI-orange)

## ✨ Features

- **📱 APK Static Analysis** — Extracts permissions, API calls, call graphs, URLs, IPs using androguard
- **🕸️ Knowledge Graph** — Builds a Neo4j Malware Knowledge Graph connecting APK components
- **🤖 Multi-Agent AI** — Specialized GenAI agents for behavioral analysis, code interpretation, and threat detection
- **📊 Risk Scoring** — Weighted 0-100 risk score with detailed breakdown
- **💬 AI Chat** — Ask natural language questions about any analyzed APK
- **📄 Report Generation** — Comprehensive Markdown reports with actionable recommendations
- **🎨 Premium UI** — Dark-themed glassmorphism interface with interactive graph visualization

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd gagma/backend
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp ../.env.example ../.env
# Edit .env with your API keys
```

**Minimum required:** Set `GEMINI_API_KEY` (free at https://aistudio.google.com/apikey)

**Optional:** 
- `NEO4J_URI`, `NEO4J_PASSWORD` — Neo4j AuraDB (free at https://neo4j.com/cloud/aura-free/)
- `VIRUSTOTAL_API_KEY` — VirusTotal (free at https://virustotal.com)

### 3. Run
```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Open http://localhost:8000 in your browser.

## 🏗️ Architecture

```
APK Upload → Static Analysis (androguard) → Knowledge Graph (Neo4j)
                                                    ↓
                                            Multi-Agent GenAI
                                         ┌──────────┼──────────┐
                                    Graph Query  Behavioral  Threat Intel
                                      Agent      Agent        Agent
                                         └──────────┼──────────┘
                                                    ↓
                                         Risk Score + Report + Chat
```

## 📁 Project Structure

```
gagma/
├── backend/
│   ├── main.py              # FastAPI entry point
│   ├── config.py             # Environment config
│   ├── routers/
│   │   ├── analysis.py       # APK upload & analysis
│   │   └── chat.py           # AI chat endpoint
│   ├── services/
│   │   ├── apk_analyzer.py   # Androguard static analysis
│   │   ├── graph_service.py  # Neo4j graph operations
│   │   ├── llm_service.py    # Multi-provider LLM abstraction
│   │   ├── risk_scorer.py    # Risk scoring engine
│   │   └── report_generator.py
│   ├── agents/
│   │   ├── graph_query_agent.py
│   │   ├── behavior_agent.py
│   │   ├── code_analysis_agent.py
│   │   └── threat_intel_agent.py
│   └── models/
│       └── schemas.py        # Pydantic models
├── frontend/
│   ├── index.html
│   ├── css/style.css
│   └── js/app.js
└── .env.example
```

## 🔑 Supported LLM Providers

| Provider | Env Variable | Free Tier | Model |
|----------|-------------|-----------|-------|
| **Gemini** (default) | `GEMINI_API_KEY` | ✅ Yes | gemini-2.0-flash |
| OpenAI | `OPENAI_API_KEY` | ❌ Paid | gpt-4.1-mini |
| Groq | `GROQ_API_KEY` | ✅ Yes | llama-3.3-70b |

## 📜 License

Built for PSB Cybersecurity & AI Hackathon 2026.
