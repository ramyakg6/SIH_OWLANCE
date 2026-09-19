# OwLance Backend

See the [project README](../README.md) for the full overview and demo script.

Production-ready cybersecurity risk assessment backend built with **Python 3.11**, **FastAPI**, and **SQLAlchemy** (supporting **PostgreSQL** and automatic **SQLite** local fallback).

## Core Capabilities (P0)

1. **`POST /consent`**:
   - Records assessment authorization, requester IP, version, and active scan permission to the `consent_log` table.
2. **`GET /scan/{domain}`**:
   - Passive attack surface discovery via **Certificate Transparency** (`crt.sh`) and **DNS enumeration** (`dnspython`: A, AAAA, MX, TXT).
   - In-depth SPF, DKIM, and DMARC email hygiene validation.
   - 24-hour TTL caching on all external responses with exponential backoff (`tenacity`).
   - Persists assets to `assets` table.
   - Evaluates findings with composite risk scoring and persists to `findings` table.
3. **Bounded scanning**: Targets are prioritised by how interesting the hostname
   is, capped at `MAX_SCAN_TARGETS`, resolved in a thread pool, and held to
   `SCAN_DEADLINE_SECONDS`. The endpoint returns partial results rather than
   hanging when an intel feed is slow or unreachable.
4. **Composite Risk Scoring Engine**:
   - Formula:
     $$\text{Final\_Risk\_Score} = \text{EPSS\_score} \times \text{CVSS\_weight} \times \text{CWE\_weight} \times \text{Exposure\_Multiplier} \times \text{Asset\_Criticality\_Weight}$$
   - **FIRST.org EPSS API** for exploit probability.
   - **NVD API** with automatic **OSV.dev** fallback.
   - **CISA KEV catalog**: Hard-escalates any catalog CVE to **Critical** regardless of computed score.
   - **Zero fake data policy**: Returns lower confidence with explicit data unavailable indicators if external threat feeds fail and no cache exists.
   - Maps org security score to canonical **300–900** range.
   - **Unknown is not clean**: a domain whose discovery failed returns a neutral
     score rather than 900, and partial coverage is capped below a perfect score
     with a note explaining the cap.
5. **`POST /optimize`**:
   - Greedy ratio knapsack optimizer for security remediation budgets.
   - Free fixes (`cost == 0`) are selected unconditionally first.
   - Non-zero fixes are ranked by efficiency ratio `(reduction / cost)` descending.
   - Reuses `compute_org_score()` to project score improvement without fabricated metrics.
   - Benchmarked to execute in $< 5\text{ms}$ for 5–50 findings.

## Setup & Running

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Run the Development Server

Run from **this** directory (`backend/`), so that `app` is importable:

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

No database setup is needed: tables are created on boot in a local SQLite file
(`owlance.db`). Point `DATABASE_URL` at PostgreSQL in `.env` to use that
instead; if it is unreachable the backend falls back to SQLite rather than
failing to start.

Interactive API documentation will be available at:
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

### 3. Run Automated Tests
```powershell
pytest tests/ -v
```

31 tests, covering discovery, threat-intel fallbacks, scoring, the optimizer,
scan bounding, and graceful degradation.
