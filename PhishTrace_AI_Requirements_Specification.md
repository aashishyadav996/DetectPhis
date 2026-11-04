# PhishTrace AI — Requirements Specification (Phase 0)

**Full Title:** PhishTrace AI: An Explainable Multi-Signal Framework for Early Detection and Investigation of Phishing URLs
**Document status:** Baseline requirements, agreed after Phase 0 scoping discussion
**Project type:** BCA Final Year Project — Cybersecurity Specialization

---

## 1. Project Summary

PhishTrace AI is a phishing URL investigation platform that treats reputation services (VirusTotal) as *one evidence source* among several, rather than the sole verdict. It combines URL lexical analysis, brand impersonation detection, a trained ML classifier, and lightweight infrastructure/domain correlation into a single explainable risk assessment, with a particular research focus on URLs that have little or no existing reputation-based detection ("low-reputation" URLs).

### Research Question
Can a multi-signal system detect suspicious phishing URLs that reputation-based systems may not yet identify?

### Hypothesis
A multi-signal risk engine combining reputation, URL features, ML, brand impersonation, and contextual threat intelligence can provide earlier and more explainable phishing detection than relying on reputation alone. This is treated as a hypothesis to be tested with real experimental results, not a guaranteed conclusion.

### Novelty Statement (for report/viva — avoid overclaiming)
The individual techniques used (URL feature extraction, brand similarity scoring, ML phishing classification, VirusTotal lookups) are each independently known in prior research and industry tools. The novelty of this project lies in the **specific integration, correlation methodology, explainability layer, and experimental evaluation** — particularly the low-reputation detection experiment — not in inventing a new detection primitive from scratch.

---

## 2. Locked Decisions (from Phase 0 discussion)

| Area | Decision | Rationale |
|---|---|---|
| Timeline | 3+ months available | Full planned feature set is realistic without aggressive descoping |
| Threat Relationship Graph | Free-tier only for core build: WHOIS + registrable-domain-family relationships. Paid infra APIs (Shodan/SecurityTrails) are an optional stretch goal, not a dependency | Avoids the project depending on a limited paid query quota running out before submission |
| VirusTotal API | Free tier (~4 req/min, 500 req/day). No key obtained yet — must be registered before Phase 3 | Rate limits directly shape caching design and experiment dataset size |
| Evaluation dataset size (Phase 7) | 300–500 URLs | Fits within free VT daily quota with caching, processable within 1–2 days |
| Training data | PhishTank (phishing) + Tranco top-ranked domains (legitimate) as primary; UCI Phishing Websites (2012) dataset as a baseline/comparison model only | PhishTank's live/hourly nature supports the low-reputation experiment; UCI dataset is small, well-documented, and lets results be contextualized against prior published work |
| Frontend | React (Vite) | Lighter setup than Next.js; SSR not needed for a dashboard app |
| Backend | Python FastAPI | Shares language with ML pipeline; async support; auto-generated OpenAPI docs support the API documentation requirement |
| ML | scikit-learn (+ optionally LightGBM) | Interpretable, appropriate for dataset size, avoids unjustified deep-learning complexity |
| Database | PostgreSQL, hosted on Neon | Neon's free tier is persistent (no 30-day deletion) and includes connection pooling, unlike Render's free Postgres |
| Graph storage | Relational table + frontend graph visualization library (no Neo4j) | Avoids running/hosting a second database for a feature that is UI-facing, not query-heavy |
| Auth | JWT | Stateless, standard for a SPA + REST API split |
| Containerization | Docker Compose | Enables one-command local demo of full stack |
| Hosting | Vercel (frontend) + Render (backend) + Neon (database), all free tier | No credit card required; verified against current (Aug 2026) provider documentation |
| Access model | Public, open signup | Requires SSRF protection and rate limiting to be in place **before** the link is shared publicly — treated as a hard prerequisite, not a later cleanup task |

### Known constraints to carry into later phases
- Render's free web service spins down after 15 minutes of inactivity, with 30–60 second cold-start latency on the next request. The frontend must show a clear "waking up the server" loading state so this isn't mistaken for a broken deployment during a viva demo.
- VirusTotal free tier quota must be respected via server-side caching of results (by normalized URL) from day one — not retrofitted later.
- Domain age / WHOIS data availability and reliability varies by TLD and by which free WHOIS service is used. This must be verified experimentally during implementation, not assumed to work uniformly.
- The UCI dataset is from 2012; it is explicitly scoped as a *baseline comparison model only*, not the primary training data, and this limitation must be stated in the final report.

---

## 3. System Architecture (high level)

```
React SPA (Vercel)
     │  HTTPS + JWT
     ▼
FastAPI Backend (Render)
     │
     ├── auth/                  JWT issuance, password hashing
     ├── analyze orchestrator   URL normalization + SSRF-safe fetch validation
     │        │
     │        ├── url_features/         lexical/structural feature extraction
     │        ├── brand_detector/       Jaro-Winkler + homoglyph normalization
     │        ├── threat_intelligence/  VirusTotal client + evidence normalizer + cache
     │        ├── ml/                   trained model + prediction service
     │        └── risk_engine/          signal correlation + explainability
     │
     ├── graph/                 WHOIS + domain-family relationship builder
     ├── reports/                investigation report generator
     └── database/               PostgreSQL (Neon): User, Scan, URL, Domain, Evidence, etc.
```

Each backend module maps to its own folder (`frontend/`, `backend/`, `ml/`, `risk_engine/`, `threat_intelligence/`, `brand_detector/`, `graph/`, `database/`, `tests/`, `docs/`, `scripts/`) per the modularity requirement — no monolithic files.

---

## 4. Feature Scope

### Primary Innovations (must-have)
1. Low-Reputation Early Warning
2. Explainable Multi-Signal Risk Engine
3. Threat Relationship Investigation Graph (free-tier scope)

### Secondary Innovations (planned, standard build)
4. Brand Impersonation Detection
5. Adversarial URL Mutation Testing
6. Detection Confidence (separate from Risk Score)
7. Personal Cybersecurity Risk Profile
8. Evidence-based Investigation Reports

### Explicitly descoped / deferred
- Neo4j graph database — replaced with relational storage + frontend visualization
- Redis — deferred unless real caching/rate-limit pain is observed during development
- Learned/calibrated signal weighting — manual, explained, configurable weights used instead, with the choice justified in the report as the academically defensible option given available data volume
- Paid infrastructure correlation (Shodan/SecurityTrails) — optional stretch goal only

---

## 5. Security Requirements (non-negotiable given public access)

- SSRF protection on all URL-fetching functionality (block internal/private IP ranges, cloud metadata endpoints, non-HTTP(S) schemes)
- Input validation and URL normalization before any processing
- Per-IP and per-account rate limiting (protects both the app and the VT quota)
- Secure password hashing, JWT handling, and secrets management via environment variables only — never in frontend code, logs, or the public repo
- CSRF protection where applicable, secure headers, SQL injection and XSS prevention
- Audit logging for login, analysis requests, report generation, and admin actions — explicitly excluding API keys, passwords, and unnecessary sensitive data
- Security review (Phase 5) must be completed **before** the public link is shared or demoed

---

## 6. Anti-Fabrication Commitments

The following will never be presented as real results before they are actually produced:
- VirusTotal results, threat intelligence, domain age, IP relationships
- ML accuracy/precision/recall/F1/ROC-AUC figures
- Dataset statistics
- Adversarial testing detection rates
- Any experimental comparison numbers (Systems A/B/C/D)

Anywhere a number is needed before it has been measured, this document (and all subsequent work) will state explicitly: *"This must be measured/queried during implementation."* Mock data will only appear in early UI prototyping and will be clearly labeled as mock data.

---

## 7. Open Items for Later Phases

These are flagged now so they aren't forgotten, but don't block starting Phase 1:
- Exact WHOIS data source/library to use (needs a small evaluation of 2–3 free options for reliability)
- Final confirmation of dataset row counts once actually downloaded (published figures vary across sources and must be verified firsthand)
- Whether the paid infra-correlation stretch goal gets attempted, revisited once core build is stable

---

## Next Step

Proceed to **Phase 1 — Architecture**: detailed component architecture, database ER design, and REST API specification, built on the decisions above.
