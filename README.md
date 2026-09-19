# OwLance

**AI-Powered Continuous Cyber Risk Quantification and Investment Optimization Platform**
SIH26105 · AICTE · Theme: Blockchain & Cybersecurity

Most cyber risk tools tell a business "Low / Medium / High" — which tells a CISO
or a small-business owner nothing about how much money is actually at stake.
RiskLens gives budget-constrained organizations a transparent, auditable risk
score benchmarked against real breach data, translated directly into rupee
terms and a ranked, budget-aware action plan.

📖 **[See the full product walkthrough with screenshots →](docs/WALKTHROUGH.md)**

---

## Live Demo

- **Frontend:** `[your Vercel URL]`
- **Backend API docs:** `[your Render URL]/docs`

*(First load on the deployed backend may take 30–60 seconds to wake up on the
free tier — this is expected, not a bug.)*

---

## What it looks like

![Dashboard](docs/screenshots/05-dashboard.png)
*One score (0–900), Expected Annual Loss, and potential savings — all computed
live from a real scan, not placeholder data.*

![Investment Optimizer](docs/screenshots/07-investment-optimizer.png)
*The core differentiator: drag the budget slider and a greedy-ratio knapsack
algorithm live-recalculates which fixes to prioritize, free fixes first.*

More screens — onboarding, live scanning, the vulnerability risk matrix, the
causal risk graph, the Risk Passport, and the API docs — are in the
**[full walkthrough](docs/WALKTHROUGH.md)**.

---

## How it works

1. **Deterministic core, AI explains** — the scoring engine and optimizer are
   rule-based and fully auditable. No AI/LLM ever generates a risk number.
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

## Tech Stack

**Backend:** Python, FastAPI, PostgreSQL (SQLite fallback for local dev), SQLAlchemy
**Frontend:** React, Vite, Tailwind CSS
**Data sources:** crt.sh (Certificate Transparency), NVD, FIRST.org EPSS, CISA KEV

## Running locally

```powershell
git clone https://github.com/ramyakg6/SIH_OWLANCE.git
cd SIH_OWLANCE
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\run.ps1
```

- Backend: http://127.0.0.1:8000/docs
- Frontend: http://localhost:5173

## Team

`[names here]`
