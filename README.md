# RiskLens (OwLance)

**AI-Powered Continuous Cyber Risk Quantification and Investment Optimization Platform**
SIH26105 · AICTE · Theme: Blockchain & Cybersecurity

---

## 🔗 Live Demo

- **Frontend:** `[your Vercel URL]`
- **Backend API docs:** `[your Render URL]/docs`

*(First load on the deployed backend may take 30–60 seconds to wake up on the
free tier — this is expected, not a bug.)*

---

Most cyber risk tools tell a business "Low / Medium / High" — which tells a CISO
or a small-business owner nothing about how much money is actually at stake.
RiskLens gives budget-constrained organizations a transparent, auditable risk
score benchmarked against real breach data, translated directly into rupee
terms and a ranked, budget-aware action plan. The business also gets a
shareable Risk Passport it can hand to a bank or insurer to prove its
security posture — without exposing what's still open.

📖 **[See the full step-by-step walkthrough with screenshots →](docs/WALKTHROUGH.md)**

---


## What it looks like

![Consent](docs/screenshots/03-consent.png)
*Consent-first by design: active scanning only runs after explicit, logged
authorization — every scan action is written to a tamper-evident audit log.*

![Dashboard](docs/screenshots/05-dashboard.png)
*One score (0–900), Expected Annual Loss, and potential savings — all computed
live from a real scan, not placeholder data.*

![Investment Optimizer](docs/screenshots/07-investment-optimizer.png)
*Drag the budget slider and a greedy-ratio knapsack algorithm live-recalculates
which fixes to prioritize, free fixes first.*

![Causal Risk Graph (Simulated)](docs/screenshots/10-causal-risk-graph-simulated.png)
*Attack-Path Collapse: Threat → Vulnerability → Asset → Identity → Control Gap
→ Business Service → Financial Loss. The same graph starts sparse on an
external-only scan and densifies automatically as more data sources connect —
one adaptive engine, not a separate SME/enterprise tier.*

More screens — onboarding, live scanning, the vulnerability risk matrix, and
the API docs — are in the **[full walkthrough](docs/WALKTHROUGH.md)**.

## 🛡️ The Risk Passport — why RiskLens is different

![Risk Passport](docs/screenshots/08-risk-passport.png)
*Most tools score a company secretly, for the vendor's own dashboard. The Risk
Passport flips that: it's a shareable, verifiable proof of security posture —
owned and controlled by the business itself, backed by a tamper-evident
hash-chain, and deliverable straight to WhatsApp so an owner doesn't need to
log into a dashboard to prove their posture to a bank, insurer, or client.
This is the feature that turns a risk score into something the business can
actually *use* — not just look at.*


---

## 🚀 Features

- **Consent-first active scanning** — active checks run only after explicit,
  logged authorization; every scan action lands in a tamper-evident audit log
- **Benchmark-driven risk scoring** — a 0–900 composite score and Expected
  Annual Loss, calibrated to sector- and size-matched breach-cost benchmarks
  rather than hand-tuned FAIR inputs
- **Contextual vulnerability scoring** — CVSS + FIRST.org EPSS + CISA KEV,
  plotted on an Impact × Likelihood risk matrix
- **Causal risk graph** — an adaptive Threat → Vulnerability → Asset →
  Identity → Control Gap → Business Service → Financial Loss chain that
  densifies as more data sources connect
- **Investment optimizer** — greedy-ratio knapsack algorithm that
  live-recalculates which fixes to prioritize under a budget slider, always
  surfacing free fixes first, with ROSI per recommendation
- **AI ChatBot** — a plain-English chat layer so a non-technical owner can
  ask "what's our highest financial risk today?" instead of reading a risk
  matrix; it only explains numbers the deterministic engine already
  computed, it never generates a score or a finding itself
- **Risk Passport** — a shareable, hash-chained proof of security posture,
  owned by the business and deliverable straight to WhatsApp — our core
  differentiator, see above
- **Passive-first discovery** — subdomain and asset discovery via Certificate
  Transparency logs and DNS, with zero setup and no authorization required
- **REST API** — full FastAPI backend with auto-generated Swagger/ReDoc docs

---

## How it works

1. **Deterministic core, AI explains** — the scoring engine and optimizer are
   rule-based and fully auditable. No AI/LLM ever generates a risk number;
   the Risk Copilot chat only translates numbers the deterministic engine
   already computed into plain English for non-technical staff.
2. **Consent-first, passive-first** — active scanning only runs after
   explicit, logged authorization. Passive discovery is always on.
3. **Statistically honest** — financial exposure is always shown as a range
   (median / P90 / P99) with a confidence score, never a single fake-precise
   number.
4. **Benchmark-driven** — since small businesses can't manually calibrate
   FAIR-style probability inputs, financial modeling uses sector- and
   size-matched breach-cost benchmark data.
5. **One adaptive engine, not two tiers** — the same causal risk graph starts
   sparse (external-only) and fills in automatically as more data sources
   connect. There's no separate "SME version" and "enterprise version."

---

## 📁 Project Structure

```
owlance/
├── src/                        # Frontend (React + Vite)
│   ├── App.jsx
│   ├── OwLance.jsx
│   ├── components/
│   ├── lib/
│   └── assets/
├── public/                     # Static assets
├── backend/                    # Backend (FastAPI + Python)
│   ├── app/
│   │   ├── main.py             # FastAPI application
│   │   ├── config.py
│   │   ├── db/                 # SQLAlchemy models + session
│   │   ├── routers/            # API routes (auth, scan, consent,
│   │   │                       #   optimizer, connectors, analytics, whatsapp)
│   │   ├── schemas/            # Pydantic schemas
│   │   └── services/           # Scoring, optimizer, scanners, threat intel
│   ├── tests/                  # Pytest test suite
│   ├── requirements.txt
│   └── .env.example
├── scripts/                    # Build/smoke-test helper scripts
├── docs/                       # This walkthrough + screenshots
├── run.ps1 / run.sh            # One-command local startup
├── vite.config.js
└── package.json
```

---

## 🛠️ Running locally

```powershell
git clone https://github.com/ramyakg6/SIH_OWLANCE.git
cd SIH_OWLANCE
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\run.ps1
```

- Backend: http://127.0.0.1:8000/docs
- Frontend: http://localhost:5173

`run.ps1` / `run.sh` sets up the backend virtual environment, installs
frontend dependencies, and starts both servers. `backend/.env.example` seeds
a demo account (`demo@owlance.in` / `owlance2026`) on first boot so a fresh
clone is reachable with zero setup — the database falls back to SQLite
automatically if PostgreSQL isn't configured.

---

## 🔧 Tech Stack

## 🔧 Technology Stack

### Backend

- **FastAPI** — High-performance async web framework
- **SQLAlchemy** — ORM for PostgreSQL (with automatic SQLite fallback for local dev)
- **Pydantic** — Data validation and settings management
- **PyJWT** — Session token signing for auth

### Frontend

- **React 19** — Component-based UI
- **Vite** — Dev server and build tooling, zero-config
- **Tailwind CSS** — Utility-first styling
- **Recharts** — Dashboard charts (score build-up, risk trend, loss exceedance curve)

### Data Sources

- **crt.sh** — Certificate Transparency logs for passive subdomain discovery
- **NVD** — CVE data for vulnerability scoring
- **FIRST.org EPSS**

---

## Team

`[names here]`
