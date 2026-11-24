# PhishTrace AI

<div align="center">

![PhishTrace AI Banner](https://raw.githubusercontent.com/aashishyadav996/PhishTrace-AI/main/static/img/brand-banner.svg)

### Detect. Analyze. Protect. Stay One Step Ahead of Phishing.

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%20%2F%20FastAPI-green?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![React](https://img.shields.io/badge/Frontend-React%20%2F%20Vite-61dafb?logo=react&logoColor=black)](https://vitejs.dev/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Audit%20Passed-brightgreen)](SECURITY_NOTES.md)
[![Vercel](https://img.shields.io/badge/Vercel-phishtrace--ai-black?logo=vercel&logoColor=white)](https://vercel.com/)

**An explainable, multi-signal phishing detection and cyber investigation platform designed to identify zero-day and low-reputation phishing threats before signature databases catch up.**

[Explore Features](#-key-features) • [Quick Start](#-installation--setup) • [Architecture](#-system-architecture) • [Usage Guide](#-usage-guide) • [Deployment](#-deployment-instructions) • [Security](#-security-considerations)

</div>

---

## 📌 Project Overview

**PhishTrace AI** is an advanced cybersecurity threat intelligence and URL forensic investigation platform. Traditional security tools rely heavily on commercial reputation blocklists (such as VirusTotal or Google Safe Browsing). However, novel, short-lived phishing campaigns—often created minutes before launching an attack—frequently exhibit a clean reputation score, bypassing conventional security gates.

PhishTrace AI addresses this critical vulnerability by implementing an **Explainable Multi-Signal Risk Engine**. By cross-correlating structural lexical patterns, brand impersonation markers, machine learning inference, autonomous threat relationship graphs, and DNS/RDAP infrastructure telemetry, PhishTrace AI delivers rapid, interpretable risk assessments and early warnings even when reputation providers report zero detections.

---

## 🏗️ System Architecture

PhishTrace AI operates on a modular, multi-tier forensic architecture that decomposes every candidate target across independent intelligence vectors:

```
                                  ┌──────────────────────────┐
                                  │   User / Analyst Input   │
                                  │   (URL, Email ID, .eml)  │
                                  └────────────┬─────────────┘
                                               │
                                 ┌─────────────▼─────────────┐
                                 │   URL Safety Normalizer   │
                                 │  (SSRF Guard, RFC Syntax) │
                                 └─────────────┬─────────────┘
                                               │
     ┌──────────────────────┬──────────────────┼───────────────────┬──────────────────────┐
     │                      │                  │                   │                      │
┌────▼─────────────┐ ┌──────▼───────────┐ ┌────▼─────────────┐ ┌───▼──────────────┐ ┌─────▼────────────┐
│ Lexical Analysis │ │ Brand Detector   │ │ ML Predictor     │ │ Threat Intel     │ │ Threat Graph     │
│ - Structure      │ │ - Homoglyphs     │ │ - Random Forest  │ │ - VirusTotal v3  │ │ - DNS A / MX     │
│ - Keywords       │ │ - Jaro-Winkler   │ │ - Probability    │ │ - Cache Layer    │ │ - RDAP / WHOIS   │
│ - URL Encoding   │ │ - Masquerading   │ │ - Structural Feat│ │ - Inconclusive W │ │ - Network Nodes  │
└────┬─────────────┘ └──────┬───────────┘ └────┬─────────────┘ └───┬──────────────┘ └─────┬────────────┘
     │                      │                  │                   │                      │
     └──────────────────────┼──────────────────┼───────────────────┴──────────────────────┘
                            │
               ┌────────────▼──────────────┐
               │ Multi-Signal Risk Engine  │
               │ - Dynamic Weights         │
               │ - Explainable Factors     │
               │ - Confidence Scoring      │
               │ - Reputation Gap Alert    │
               └────────────┬──────────────┘
                            │
     ┌──────────────────────┼────────────────────────┐
     │                      │                        │
┌────▼──────────────┐ ┌─────▼───────────────┐ ┌──────▼──────────────┐
│ Forensic UI       │ │ Adversarial Suite   │ │ Export Reports      │
│ - Cyber Dashboard │ │ - Mutation Attacks  │ │ - Signed HTML       │
│ - Graph Explorer  │ │ - Evasion Scoring   │ │ - Cryptographic JSON│
└───────────────────┘ └─────────────────────┘ └─────────────────────┘
```

---

## 🛡️ Key Features

### 1. 🔍 Explainable Multi-Signal Risk Engine
- **Transparent Attribution:** Rather than outputting an opaque score, the engine computes normalized weights across Lexical, Brand, Machine Learning, Threat Intel, and Domain signals.
- **Dynamic Reasoning:** Enumerates concrete positive risk contributors (reasons increasing risk) and mitigating security signals (reasons decreasing risk).
- **Dual Metric Assessment:** Calculates both **Risk Score** (0–100 scale: `SAFE`, `LOW RISK`, `SUSPICIOUS`, `HIGH RISK`) and an independent **Confidence Score** (based on available signal completeness).
- **Reputation Gap Warning:** Proactively flags suspicious domains where reputation feeds report zero detections despite high structural anomalies.

### 2. 🎭 Brand Impersonation & Homoglyph Detector
- Detects targeted brand spoofing across international financial, tech, social, and e-commerce brands.
- Uses **Jaro-Winkler** and **Levenshtein** distance algorithms tuned for cybersecurity evasion detection.
- Uncovers advanced evasion techniques:
  - **Homoglyph replacement:** Character swapping (e.g., Cyrillic or numeric replacements: `paypa1`, `micros0ft`).
  - **Subdomain nesting:** Masquerading via multi-level subdomains (`paypal.com.account-verify.xyz`).
  - **Hyphenated padding:** Combining high-profile brand names with credential harvest keywords (`secure-apple-id-login`).

### 3. 🌐 Interactive Threat Relationship Graph
- Dynamically maps target infrastructure relationships into an interactive node visualizer.
- Correlates DNS records (`A`, `MX`, `NS`), resolved IP addresses, Autonomous System Numbers (ASN), and RDAP registration data.
- Color-coded forensic severity highlighting suspicious domain registration age (<180 days), shared hosting infrastructure, and unroutable MX configurations.

### 4. ⚔️ Adversarial URL Evasion Suite
- Stress-tests detection robustness against automated mutation attacks:
  - Typosquatting (omission, repetition, transposition)
  - Subdomain nesting & masquerading
  - Userinfo destination masking (`user@target.com`)
  - Alternative TLD substitution
- Evaluates real-time engine resilience score (% of mutations successfully caught).
- Provides actionable vulnerability recommendations for edge-case coverage.

### 5. 📧 Email & Cryptographic Forensics
- **Email ID Investigator:** Evaluates sender email addresses, local-part entropy, syntax compliance, disposable burner domains, and mail server (MX) routability.
- **Email Message Dissection (.eml):** Parses email headers, extracts embedded URLs, evaluates sender alignment, and checks SPF/DKIM/DMARC authentication status.
- **Cryptographic File Hashing:** Computes real-time **MD5**, **SHA-1**, and **SHA-256** checksums for suspect file attachments to support forensic integrity and cross-referencing.

### 6. 📄 Verifiable Investigation Reports & Audit History
- Generates downloadable, standalone **Executive HTML** and **Machine-Readable JSON** investigation reports.
- Includes cryptographic verification hash (`SHA-256`) to ensure chain-of-custody integrity for security audits.
- Full local SQLite database tracking previous investigations with single-click reload capability.

---

## 💻 Technology Stack

| Layer | Technologies |
|---|---|
| **Core Application Backend** | Python 3.11+, Flask 3.0+, Werkzeug |
| **API & Microservice Alternative** | FastAPI, Uvicorn, Pydantic v2 |
| **Machine Learning** | Scikit-learn (RandomForestClassifier), NumPy, Joblib |
| **Forensics & Networking** | TLDextract, dnspython, Requests, Cryptography |
| **Database & Persistence** | SQLAlchemy 2.0, SQLite (default local) / PostgreSQL (Neon/Production) |
| **User Interface** | Semantic HTML5, CSS3 (Forensic Dark Mode theme), Vanilla JS, SVG Gauges |
| **Modern SPA Option** | React 18, Vite, Lucide Icons |
| **DevOps & Containers** | Docker, Docker Compose |
| **Target Deployment** | Vercel (Frontend / Serverless), Render / Railway (Production WSGI) |

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.11 or newer installed.
- Git installed on your system.

### Option 1: Local Standard Setup (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/aashishyadav996/PhishTrace-AI.git
   cd PhishTrace-AI
   ```

2. **Create and activate a virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **macOS / Linux:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**
   - Copy `.env.example` to `.env`:
     - **Windows:** `Copy-Item .env.example .env`
     - **Linux/macOS:** `cp .env.example .env`
   - Configure your preferred settings (see [Environment Variables](#-environment-variables)).

5. **Start the application:**
   ```bash
   python app.py
   ```

6. **Access the Dashboard:**
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

### Option 2: Docker Setup

To build and run PhishTrace AI in an isolated container:

```bash
docker build -t phishtrace-ai .
docker run -p 5000:5000 phishtrace-ai
```

Or using Docker Compose:
```bash
docker-compose up --build
```

---

## ⚙️ Environment Variables

Configure application settings in your `.env` file:

```ini
# Application Environment
APP_ENV=development
FLASK_ENV=development
HOST=127.0.0.1
PORT=5000
SECRET_KEY=dev-phishtrace-secret-key-change-in-production
MAX_CONTENT_LENGTH=10485760

# Optional Threat Intelligence API Keys (Keep private!)
# Register free at: https://www.virustotal.com/
VIRUSTOTAL_API_KEY=

# Database Configuration (Leave blank for default SQLite: data/phishtrace.db)
DATABASE_URL=
```

> [!NOTE]
> PhishTrace AI operates completely autonomously without external API keys. If `VIRUSTOTAL_API_KEY` is not provided, the multi-signal engine automatically redistributes signal weights across lexical, brand, machine learning, and infrastructure signals.

---

## 📖 Usage Guide

### 1. Investigating Suspicious URLs
1. Open the dashboard at `http://127.0.0.1:5000`.
2. Enter any candidate URL in the search bar (e.g., `paypa1-security-update.com/signin`).
3. Click **Scan URL** or select one of the built-in forensic sample pills.
4. Review the **Risk Gauge**, **Confidence Rating**, **Attribution Breakdown**, and **Brand Impersonation Summary**.

### 2. Exploring Threat Relationship Graphs
1. Switch to the **Threat Relationship Graph** tab.
2. Inspect the connected nodes linking the URL, Registrar, Apex Domain, and IP address.
3. Review the live telemetry ribbon displaying domain age and nameserver infrastructure.

### 3. Running Adversarial Evasion Tests
1. Click the **Adversarial Testing** tab.
2. Click **Run Evasion Test Suite** to simulate real-world bypass attempts against the engine.
3. Observe which mutations triggered alerts (`FLAGGED`) and read automated vulnerability mitigations.

### 4. Dissecting Email & Files
1. Navigate to the **Email & File Forensics** tab.
2. Choose between:
   - **Email ID Lookup:** Verify mailbox routability and disposable domains.
   - **.eml Dissection:** Upload an email message file to extract embedded links and verify authentication.
   - **File Hashing:** Calculate cryptographic hashes (MD5, SHA-1, SHA-256) for suspicious attachments.

### 5. Exporting Audits & Reports
1. In the overview tab, click **Export Report (HTML)** for a client-ready forensic dossier.
2. In the **Audit History** tab, view all historical scans and click **Load** to reload any previous scan state.

---

## 🔒 Security Considerations

- **Loopback Enforcement:** By default, the development server binds strictly to `127.0.0.1` and blocks non-loopback clients to protect local scan history and configuration.
- **SSRF Prevention:** URL normalization validates schemes, rejects credentials in URLs (`user:pass@host`), and blocks invalid port structures. Analysis is performed through string decomposition and passive metadata queries without fetching hostile active content.
- **Strict Content Security Policy (CSP):** The application serves strict CSP headers (`default-src 'self'`, no inline scripts) to mitigate Cross-Site Scripting (XSS).
- **Upload Boundaries:** File uploads are strictly capped at 10 MiB, quarantined in memory, and never executed.
- **Credential Hygiene:** No sensitive API keys or personal credentials are included in the source code or repository history.

---

## 🌐 Deployment Instructions

### Production Deployment (WSGI / Docker)
For deploying to production servers (AWS EC2, DigitalOcean, Railway, or Render):
1. Use a production WSGI server such as **Gunicorn**:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```
2. Place behind a reverse proxy (**Nginx** or **Caddy**) with SSL/TLS termination.
3. Set `APP_ENV=production` and generate a strong 64-character `SECRET_KEY`.

### Vercel Deployment (`phishtrace-ai`)
For deploying the modern React interface to Vercel:
1. Navigate to `frontend/`:
   ```bash
   cd frontend
   npm install
   npm run build
   ```
2. Connect the repository to your Vercel account under project name **phishtrace-ai**.
3. Set the root directory to `frontend` with output directory `dist`.

---

## 🔮 Future Scope & Roadmap

- [ ] **Expanded ML Training Pipeline:** Integration with continuous PhishTank and Tranco datasets for monthly automated retraining.
- [ ] **Browser Extension:** Lightweight Chromium/Firefox extension utilizing PhishTrace AI's inference API for real-time web navigation alerts.
- [ ] **Sandboxed Headless Screenshot Engine:** Optional headless browser snapshot rendering within an isolated container.
- [ ] **Multi-Tenant User Authentication:** Role-based access control (RBAC) and team workspaces for enterprise SOC environments.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author & Repository

- **Project:** PhishTrace AI
- **Repository:** [https://github.com/aashishyadav996/PhishTrace-AI](https://github.com/aashishyadav996/PhishTrace-AI)
- **Author:** [aashishyadav996](https://github.com/aashishyadav996)
- **Category:** AI-Powered Cybersecurity Web Application
