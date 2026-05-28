# 🕸️ GAGMA Enterprise — Graph-Augmented GenAI Malware Analyst (v2.0)

> **A State-of-the-Art Cybersecurity Operations Command Center for Android Banking Threat Mitigation.**  
> Built to align with **RBI Master Directions on Digital Payment Security Controls** and **CERT-In Cyber Incident Response SLAs**.

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-00f0ff?style=flat-square&logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-00ff66?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Neo4j](https://img.shields.io/badge/Neo4j-Graph%20Knowledge-007cc2?style=flat-square&logo=neo4j)](https://neo4j.com/)
[![Gemini AI](https://img.shields.io/badge/Google%20Gemini-Pro-orange?style=flat-square&logo=google)](https://ai.google.dev/)
[![Caddy](https://img.shields.io/badge/Caddy-Reverse%20Proxy-white?style=flat-square&logo=caddy)](https://caddyserver.com/)

---

## 📺 Tactical Command Center Dashboard
GAGMA has been refactored from a simple analysis script into a **multi-million-dollar Military Cyber Command Center (Aviation HUD Dark Theme)**.

```
       [ GAGMA CYBER OPS - REAL-TIME DETECTIONS & INCIDENT RESPONSE ]
┌─────────────────────────────────────────────────────────────────────────┐
│ [STATIONS]  [COMPLIANCE INDICATORS]     [THREAT SCATTER FEED]           │
│ ■ Caddy       ■ CERT-In SLA: 100%       ■ 22:42:01 - Blocking Drinik v3 │
│ ■ FastAPI     ■ RBI Controls: Passed    ■ 22:41:30 - Blocked 45.132.75.22│
│                                                                         │
│ ┌────────────────────────────────┐  ┌─────────────────────────────────┐ │
│ │      KNOWLEDGE GRAPH VIEW      │  │    CAMPAIGN CLUSTERING VIEW     │ │
│ │                                │  │                                 │ │
│ │       (APK) ──[:INVOKES]──(API)│  │     (APK-1) ──┐                 │ │
│ │         │                      │  │               ├──[C&C Server]   │ │
│ │    [:REQUESTS]                 │  │     (APK-2) ──┘                 │ │
│ │         ↓                      │  │    (Dynamic campaign visualizer)│ │
│ │    (Dangerous Perm)            │  │                                 │ │
│ └────────────────────────────────┘  └─────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔥 Enterprise Features (v2.0 Upgrades)

### 1. 🧬 Multi-APK Campaign Clustering (Graph-Based)
* **Visual Campaign Correlator:** GAGMA uses advanced intersection algorithms (powered by Neo4j & fallback Vis.js nodes) to combine multiple scanned APK signatures into a **single, interactive Campaign Correlation Network**.
* **Zero-Day Attribution:** If two completely distinct APK packages request the same dangerous permission patterns (e.g. *Accessibility Keylogging*) and connect to the same **C&C IP Address**, the graph physically clusters them together. Analysts can instantly identify coordinate threat campaigns targeted at the banking sector.

### 2. 🎛️ High-Fidelity Simulation Sandbox
* **No Malware Samples Needed:** A slide-out **Simulation Sandbox console** provides pre-configured, high-fidelity threat profiles targeting major Indian financial institutions:
  * **Drinik v3 UPI Overlay:** Intercepts UPI PINs and steals SMS OTPs via malicious Accessibility Service bindings.
  * **SBI YONO Phishing Clone:** Replicates official banking interfaces with active credential theft data flows.
  * **Clean Calculator Payload:** Simple utility used for system calibration and zero-risk validation.

### 3. 🔌 Automated Incident Response Webhooks (SIEM/MDM)
* **Real-time Alerting:** Integrates directly into bank SIEMs (Splunk, Microsoft Sentinel) or MDM endpoints.
* **Persistent Settings:** Save your receiver endpoints securely inside GAGMA's persistent SQLite threat database.
* **One-Click Connectivity Test:** Validate delivery path to live receivers (like Webhook.site) instantly with integrated payloads carrying SHA-256 hashes, risk scores, and quarantine parameters.

### 4. 📝 Automated YARA Signature Rule Generator
* **Automatic Yara Generation:** Compiles customized, industry-standard `.yar` rules mapping exact dynamic package signatures, accessibility overlays, and threat indicators on the fly.
* **One-Click Rule Download:** Download prepared `.yar` files straight to your local system to seed corporate firewalls and local threat hunting scanners.

### 5. 🛡️ Regulatory Compliance HUD
* **RBI Digital Payment Security Controls:** Evaluates codebases against strict digital transaction guidelines.
* **CERT-In SLA Tracker:** Monitors internal threat resolution speed, keeping operations inside the official Indian emergency response window.

---

## 🏗️ Technical Architecture & Pipeline

```
 Suspicious APK ────> [ Static Decompiler ] ────> [ Permission / API Classifier ]
                             │                                 │
                             v                                 v
                       [ Neo4j Graph ]              [ Dynamic Emulator Sandbox ]
                             │                                 │
                             └───────────────┬─────────────────┘
                                             v
                              [ Multi-Agent GenAI Broker ]
                                 ├─> Graph Agent (Cypher)
                                 ├─> Behavioral Agent (MITRE ATT&CK)
                                 └─> Threat Intel Agent (VT/AbuseIPDB)
                                             │
                                             v
                      [ Premium Operations Command Dashboard ]
                       ├─> Custom YARA Signature Rule
                       ├─> Multi-APK Campaign Clustering Visuals
                       └─> Background SIEM Webhook Broadcast
```

---

## ⚙️ Quick Start (Dockerized Production Deployment)

The entire architecture is containerized with **Docker Compose**, running a hardened FastAPI microservice behind a secure, autconfigured **Caddy Reverse Proxy**.

### 1. Configure the Environment
Clone the repository and copy the env example:
```bash
git clone https://github.com/shree-aru/gagma.git
cd gagma
cp .env.example .env
```
Edit `.env` to configure your keys:
```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=AIzaSy...     # Free from Google AI Studio
NEO4J_URI=bolt://localhost:7687
NEO4J_PASSWORD=password
```

### 2. Launch the Operations Center
Run Docker Compose:
```bash
sudo docker compose up -d --build
```
This boots:
* **Caddy Proxy:** Running on port `80` (handles reverse proxying and auto-HTTPS routing).
* **GAGMA Core:** Running on port `8001` (FastAPI backend + visual operations center assets).

Open **`http://localhost`** (or your server's public IP) to enter the Tactical Command Center!

---

## 📁 Repository Directory Layout

```
gagma/
├── backend/
│   ├── main.py              # FastAPI microservice entry point
│   ├── config.py            # Environment configurations & variables
│   ├── routers/
│   │   ├── analysis.py      # Real-time upload, polling, and YARA generator
│   │   ├── chat.py          # AI analyst chatbot gateway
│   │   ├── demo.py          # Isolated Sandbox simulation models
│   │   ├── prevention.py    # Auto-blocking & enterprise blocklist
│   │   └── webhooks.py      # SIEM configurations & dispatchers
│   ├── services/
│   │   ├── apk_analyzer.py  # Static code decompiler & structure analyzer
│   │   ├── database.py      # SQLite persistent settings & threat feed
│   │   ├── graph_service.py # Neo4j ingestion & Multi-APK clustering builder
│   │   ├── yara_generator.py# Dynamic YARA signature rule compiler
│   │   └── webhook_service.py # SIEM JSON notification broadcaster
│   └── agents/
│       ├── behavior_agent.py# Code pattern & MITRE ATT&CK mapping
│       └── threat_intel_agent.py # VT/AbuseIPDB enrichment broker
├── frontend/
│   ├── index.html           # Military Cyber Operations Workspace
│   ├── css/
│   │   └── style.css        # Aviation HUD glassmorphism styles
│   └── js/
│       └── app.js           # vis.js graph renders & polling handlers
└── docker-compose.yml       # Production microservice orchestrator
```

---

## 🏆 PSB Cybersecurity Alliance 2026
Designed with absolute dedication to modern, data-driven malware intelligence.
**Empower your security analysts, defend the banking sector, and hunt threats in real-time.**
