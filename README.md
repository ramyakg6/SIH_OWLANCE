# OwLance

**AI-Powered Continuous Cyber Risk Quantification and Investment Optimization Platform**
SIH Problem Statement **SIH26105**

OwLance turns an organisation's external attack surface into two numbers a
decision-maker can act on: a security score out of 900, and a prioritised list
of fixes that makes the most of a given remediation budget.

---

## Quick start

**One command:**

```bash
./run.sh          # macOS / Linux
.\run.ps1         # Windows PowerShell
```

Then open **http://localhost:5173** and sign in with the seeded demo account:

```
demo@owlance.in  /  owlance2026
```

Or click **Continue without an account** — scanning works signed out; only
history and the audit trail need an account.

<details>
<summary>Manual start (two terminals)</summary>

```bash
# Terminal 1 — backend
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

```bash
# Terminal 2 — frontend
npm install
npm run dev
```
</details>

No database setup is required. The backend creates a local SQLite file
(`backend/owlance.db`) on first boot.

- Frontend: http://localhost:5173
- API: http://127.0.0.1:8000
- Interactive API docs: http://127.0.0.1:8000/docs

---

## Demo script

0. **Sign in** with the demo account above, or create one. The account scopes
   your scans, score history, and audit trail; one account never sees
   another's data.
1. **Enter a domain** on the landing screen and click Continue.
2. **Business context** — industry, headcount, revenue band. These calibrate
   the financial-loss model, so the rupee figures are not generic.
3. **Data sources** — optional connectors. Each one raises scan depth and
   confidence; the UI shows exactly what each would add.
4. **Consent** — recorded to the `consent_log` table before any scanning runs.
   This is a deliberate design choice, not a formality: the assessment does not
   begin until authorisation is logged with the requester's IP.
5. **Dashboard** — score, expected annual loss, attack paths, compliance.
6. **Attack Surface → Connect a data source.** Each of the six connectors
   ingests a real export from the vendor's console. Hit **Sample** on any card
   to download a file in the right shape, then **Connect** and upload it. The
   parse result, the findings it produced, and the recomputed score all appear
   on the card. Watch the score move:

   ```
   passive scan only   780
   + cloud             677   root account has no MFA, 2 long-lived keys
   + identity          577   MFA coverage 60%, 1 admin unprotected
   + endpoint          534   40% of fleet compliant, 3 need patching
   + siem              486   412 brute-force attempts against the VPN
   ```

7. **Optimizer** — drag the budget slider. The fix list re-ranks live, and the
   projected score is recomputed by the same scoring function that produced the
   original score, not a separate estimate.

**A banner at the top of the dashboard always states whether the data on screen
is live from the backend or the built-in sample dataset**, with the reason if it
fell back. Nothing on screen is ever ambiguous about its provenance.

---

## What is computed, not stored

Every panel below is derived from the findings a scan actually produced. None
of it is a stored constant, so all of it moves when findings change — when a
connector is added, or a fix is applied.

| Panel | How it is derived |
|---|---|
| **Compliance coverage** | Findings mapped onto named controls in NIST CSF, ISO 27001 Annex A, CIS v8, RBI and SEBI CSCRF. A control fails when an open finding sits in one of its categories. The UI lists which control failed and why. |
| **Attack paths** | Chains built from real findings: an entry-stage finding (web, network, email) provides access, an identity or cloud finding escalates it. The pivot is marked as the breakpoint — the cheapest fix that severs the chain. |
| **Category risk (radar)** | Per-category residual risk, aggregated as the same probabilistic union the org score uses, so the radar and the headline number cannot disagree. |
| **Score trend** | Real history: one point per completed scan, from the `scan_history` table. |
| **Causal risk graph** | Seven layers (threat, vulnerability, asset, identity, control gap, business service, loss) built from findings. The four findings carrying the most expected loss become dominant paths; the rest collapse into one noise node, which is what makes attack-path collapse visible. |
| **Insurance readiness** | Share of the controls underwriters ask for that could be evidenced. A control nobody can demonstrate counts as not met, so connecting a source can reveal you *fail* a control rather than pass it. |
| **Audit log** | Real events, hash-chained (below). |

Coverage counts only controls this platform can evidence from external
discovery plus connected sources. It is deliberately not a claim of full
certification — that needs evidence the platform never sees, like policies,
training records and contracts.

---

## Authentication and the audit trail

**Accounts.** Passwords are hashed with bcrypt and never stored, logged, or
returned. Sessions are stateless JWTs. Login returns one message whether the
email is unknown or the password is wrong, so responses cannot be used to
enumerate accounts. Scans, history and audit entries are scoped per account.

**Scanning works signed out.** The product should be visible before an account
exists; what an account buys is retained history and an attributable trail.

**The audit log is hash-chained.** Each entry stores a SHA-256 of its own
contents *together with the previous entry's hash*. Editing or deleting any
historical row breaks every hash after it, so the log is tamper-evident rather
than merely append-only. `GET /audit/verify` recomputes the chain from the
first entry and reports the exact row where it breaks; the Compliance page has
a **Verify chain** button that calls it.

```bash
curl http://127.0.0.1:8000/audit/verify
# {"intact": true, "entries": 7, "detail": "All 7 entries verified..."}
```

The test suite proves this by altering a row and by deleting one, and asserting
verification fails in both cases.

---

## Connectors

The six data sources are real ingests, not placeholders. Each one parses an
export that the vendor's own console produces:

| Source | Export | What it changes |
|---|---|---|
| Cloud Infrastructure | AWS IAM credential report (CSV) | Root/IAM MFA gaps, long-lived access keys |
| Email & Identity | Workspace or M365 user export (CSV) | Confirmed MFA coverage, unprotected admins |
| Endpoint (EDR) | Device compliance export (CSV) | Real patch state; severity scales with the non-compliance rate |
| SIEM / Logs | Alert history (CSV or JSON) | Raises **likelihood** — an attack being attempted is not theoretical |
| Asset Inventory / CMDB | CI list with criticality (CSV) | Replaces inferred criticality, re-weighting existing findings |
| Cyber Insurance | Policy schedule (PDF or CSV) | Coverage limit vs modelled annual loss → underinsurance gap |

Column names are matched across vendor vocabularies, so a genuine export drops
in unchanged — Google Workspace's `2sv_enrolled`, Microsoft's
`StrongAuthenticationMethods` and Okta's `factor_enrolled` all resolve to the
same MFA column. A file missing a required column is rejected with a message
naming the column, rather than silently producing an empty result.

**On the OAuth question.** These connectors ingest files rather than holding
OAuth tokens, because registering an OAuth application with AWS, Microsoft,
Google, CrowdStrike and Splunk is a vendor-review process measured in weeks.
The API form of each connector is *this same parser* behind a token — the
transport differs, the analysis does not. `GET /connectors/{source}/template`
returns a sample export for each source so the path can be exercised
immediately.

---

## Architecture

```
React 19 + Vite          FastAPI + SQLAlchemy         External intelligence
──────────────────       ────────────────────         ─────────────────────
OwLance.jsx         ──►  POST /consent          ──►   crt.sh   (CT logs)
  dashboard              GET  /scan/{domain}          DNS      (dnspython)
  optimizer              POST /optimize               FIRST.org EPSS
  attack paths                                        NVD → OSV.dev fallback
lib/api.js               SQLite / PostgreSQL          CISA KEV catalog
```

### Composite risk score

```
Final_Risk_Score = EPSS × CVSS_weight × CWE_weight × Exposure × Asset_Criticality
```

Aggregated across findings and mapped to a **300–900** band.

Anything in the **CISA KEV catalog** is escalated to Critical regardless of the
computed score — a vulnerability with confirmed exploitation in the wild is not
a statistical question.

### Budget optimizer

Greedy-ratio knapsack. Free fixes (`cost == 0`) are taken unconditionally first,
then remaining fixes are ranked by `reduction / cost` descending and packed into
the budget. Runs in well under 5 ms for realistic finding counts.

The projected score is produced by re-running `compute_org_score()` with the
selected fixes zeroed out — the same function that computed the current score.
No separate projection model, so the two numbers cannot drift apart.

---

## Design decisions worth defending

**Zero fabricated data.** If a threat feed is unreachable and no cache exists,
findings are returned with an explicit `data_unavailable` flag and reduced
confidence. The system never invents a number to fill a gap.

**Unknown is not the same as clean.** A domain that could not be reached does
*not* score 900. Discovery failure returns a neutral score, and partial coverage
is capped below a perfect score with a note explaining the cap. A scan that saw
only part of the attack surface cannot certify a clean bill of health.

**Bounded scans.** Certificate Transparency can return hundreds of hostnames for
a real domain. Targets are prioritised (hosts matching `vpn`, `mail`, `admin`,
`api`, `staging` and similar survive the cut), capped at `MAX_SCAN_TARGETS`,
resolved in a thread pool, and held to a wall-clock deadline. The endpoint
always returns — with partial results rather than a hang.

**The score aggregates as a union, not a sum.** Combined risk is
`1 - Π(1 - rᵢ)` — the chance at least one finding leads to a loss event. A
plain sum saturates after three or four real findings and pegs every
organisation at the 300 floor, which makes the score useless for tracking
improvement. The union form has diminishing returns built in.

**Consent before scanning.** `POST /consent` records domain, requester IP,
timestamp, consent version, and whether active scanning was authorised, before
any discovery runs.

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe |
| `POST` | `/consent` | Record assessment authorisation |
| `GET` | `/scan/{domain}` | Passive discovery + composite risk scoring |
| `POST` | `/optimize` | Budget-constrained remediation plan |
| `POST` | `/connectors/{source_id}` | Ingest an internal data-source export |
| `DELETE` | `/connectors/{source_id}` | Disconnect a source and recompute |
| `GET` | `/connectors/{source_id}/template` | Download a sample export |
| `POST` | `/auth/register` · `/auth/login` | Create an account, sign in |
| `GET` | `/auth/me` | Current account |
| `GET` | `/history` | Real score history for the account |
| `GET` | `/audit` | Audit log entries |
| `GET` | `/audit/verify` | Recompute and verify the hash chain |
| `GET` | `/analytics/{scan_id}` | Compliance, attack paths, category risk |

```bash
curl -X POST http://127.0.0.1:8000/consent \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","consent_version":"1.0","active_scan_allowed":false}'

curl http://127.0.0.1:8000/scan/example.com

curl -X POST http://127.0.0.1:8000/optimize \
  -H 'Content-Type: application/json' \
  -d '{"scan_id":"<scan_id>","budget":15000}'
```

---

## Verifying a change

```bash
npm run verify          # build + runtime smoke test + graph geometry
cd backend && pytest    # 146 tests
```

`npm run build` alone is not enough. It proves the bundle compiles but never
executes it, and the production minifier reorders declarations -- so a
module-initialisation error can pass the build and still blank the page under
`npm run dev`. Interaction bugs are invisible to both.

`npm run smoke` covers the two classes that have shipped broken here:
evaluating every source module through Vite's dev pipeline, and dragging the
budget slider with real pointer events to check the emitted value shape.

`npm run layout` measures the causal graph's geometry at five data densities
and fails on node overlap or clipping -- neither of which a build or a
"did it render" check can see.

---

## Tests

```bash
cd backend && pytest tests/ -v
```

146 tests covering DNS classification and email hygiene, EPSS/NVD/OSV/KEV lookups
with cache and fallback behaviour, the composite scoring formula, optimizer
selection and budget constraints, target prioritisation and capping, and the
degradation paths described above, plus all six connector parsers, their
vendor-header aliases, malformed-upload rejection, and the requirement that
connector data actually moves the organisation score — plus password hashing
and strength rules, token forgery rejection, account-enumeration resistance,
per-account history isolation, hash-chain tamper detection, and the derived
compliance and attack-path logic.

---

## Configuration

Frontend (`.env.local`):

```
VITE_API_URL=http://127.0.0.1:8000
```

Backend (`backend/.env`, see `backend/.env.example`) — all optional:

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./owlance.db` | Set to a `postgresql+psycopg2://…` URL for Postgres |
| `MAX_SCAN_TARGETS` | `25` | Hostname cap per scan |
| `SCAN_DEADLINE_SECONDS` | `45` | Wall-clock scan budget |
| `DNS_WORKERS` | `12` | Parallel DNS resolvers |
| `CACHE_TTL_HOURS` | `24` | External response cache TTL |

If `DATABASE_URL` points at PostgreSQL and the server is unreachable, the backend
falls back to SQLite automatically rather than failing to boot.

---

## Project layout

```
SIH_CYBER/
├── run.sh / run.ps1          One-command startup
├── src/
│   ├── OwLance.jsx           Dashboard, optimizer, attack paths, connectors
│   ├── lib/api.js            API client + response adapters
│   └── components/ui/        Button, slider
└── backend/
    ├── app/
    │   ├── main.py           FastAPI app, CORS, lifespan
    │   ├── config.py         Settings
    │   ├── routers/          consent, scan, optimizer, connectors, auth, analytics
    │   ├── services/         ct_search, dns_scanner, threat_intel, scoring, optimizer, cache
    │   ├── schemas/          Pydantic request/response models
    │   └── db/               SQLAlchemy models and session
    └── tests/                146 tests
```
