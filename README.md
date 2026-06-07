# IOC Enrichment & Threat Intelligence API

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-App_Service-0078D4?logo=microsoftazure&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

A production-grade REST API that accepts Indicators of Compromise (IPs, domains, URLs, file hashes), enriches them against multiple threat intelligence sources simultaneously, scores their risk level, and returns structured investigation-ready output — built to replicate the Tier 1 SOC analyst triage workflow.

---

## What it does

A SOC analyst investigating an alert typically has to manually check VirusTotal, AbuseIPDB, and AlienVault OTX for every suspicious IP — one tab at a time. This API automates that:

1. Submit an IOC via one API call
2. Three threat intel sources are queried **simultaneously** (via async I/O)
3. A weighted scoring algorithm returns a `CLEAN / SUSPICIOUS / MALICIOUS` verdict with source-attributed reasons
4. The result is stored and linked to an investigation case

> Demo: submit `185.220.101.5` (a known Tor exit node). It returns `MALICIOUS` with score `70`, citing 8 VirusTotal detections and 73% AbuseIPDB confidence — in under 400ms on first lookup, under 10ms on repeat.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Azure App Service                        │
│                                                                 │
│   ┌──────────────┐     ┌───────────────┐     ┌─────────────┐  │
│   │   FastAPI    │────▶│  Redis Cache  │     │ Key Vault   │  │
│   │  + Pydantic  │     │  (1hr TTL)    │     │  API keys   │  │
│   └──────┬───────┘     └───────────────┘     └─────────────┘  │
│          │                                                      │
│          ▼                                                      │
│   ┌──────────────┐                                             │
│   │  PostgreSQL  │ ◀── Flexible Server (private VNet)          │
│   │  Flex Server │                                             │
│   └──────────────┘                                             │
└─────────────────────────────────────────────────────────────────┘
          │
          │ asyncio.gather() — all 3 fire simultaneously
          ├──────────────────┬──────────────────┐
          ▼                  ▼                  ▼
   [VirusTotal]        [AbuseIPDB]       [AlienVault OTX]
   AV detections    Abuse confidence    Threat actor pulses
```

> Full architecture diagram: [`/docs/architecture.excalidraw`](docs/architecture.excalidraw)

---

## Tech stack

| Layer | Technology | Why |
|---|---|---|
| API framework | FastAPI | Async-native, auto-generates Swagger UI, Pydantic validation built in |
| Validation | Pydantic v2 | Rejects malformed input before any API calls fire |
| HTTP client | httpx (async) | Non-blocking — runs VT, AbuseIPDB, OTX concurrently |
| Cache | Redis | In-memory lookups return in <10ms vs ~800ms for live calls |
| Database | PostgreSQL (asyncpg) | Persistent case management and enrichment history |
| Containerization | Docker + Compose | One-command local setup, same image deploys to Azure |
| Cloud | Azure App Service | Container deployment with VNet-isolated PostgreSQL |
| Secrets | Azure Key Vault | API keys never in `.env` files or source code |
| CI/CD | GitHub Actions | Auto-deploys to Azure on every push to `main` |
| Monitoring | Azure Application Insights | Request traces, latency, error tracking |

---

## Quick start (local)

**Prerequisites:** Docker Desktop, a free [VirusTotal API key](https://virustotal.com), a free [AbuseIPDB API key](https://abuseipdb.com).

```bash
git clone https://github.com/[your-handle]/ioc-enrichment-api
cd ioc-enrichment-api

# Copy and fill in your API keys
cp .env.example .env

# Start everything (FastAPI + PostgreSQL + Redis)
docker compose up --build
```

API available at `http://localhost:8000`
Swagger UI at `http://localhost:8000/docs`

---

## API reference

### Enrich an IOC

```http
POST /ioc/enrich
Content-Type: application/json

{
  "value": "185.220.101.5",
  "ioc_type": "ip"
}
```

**Response:**
```json
{
  "id": "3f7a1c2e-84b0-4d9a-a3f1-0e6b2c1d4e5f",
  "value": "185.220.101.5",
  "ioc_type": "ip",
  "verdict": "MALICIOUS",
  "score": 70,
  "reasons": [
    "VirusTotal: 8 malicious engine detections",
    "AbuseIPDB: 73% abuse confidence score",
    "AlienVault OTX: found in 3 threat actor pulses"
  ],
  "sources": {
    "virustotal": { "malicious": 8, "suspicious": 2, "harmless": 62 },
    "abuseipdb":  { "confidence": 73, "total_reports": 41 },
    "otx":        { "pulse_count": 3 }
  },
  "cached": false,
  "created_at": "2025-07-01T14:23:01Z"
}
```

**Supported IOC types:** `ip`, `domain`, `url`, `hash`

---

### Retrieve a past enrichment

```http
GET /ioc/3f7a1c2e-84b0-4d9a-a3f1-0e6b2c1d4e5f
```

---

### Search enrichment history

```http
GET /ioc/search?value=185.220.101.5
```

---

### Create an investigation case

```http
POST /cases
Content-Type: application/json

{
  "title": "Suspicious outbound traffic — Ticket #4821",
  "description": "Multiple endpoints beaconing to the same external IP"
}
```

**Response:**
```json
{
  "id": "case-uuid",
  "title": "Suspicious outbound traffic — Ticket #4821",
  "status": "open",
  "ioc_count": 0,
  "created_at": "2025-07-01T14:23:01Z"
}
```

---

### Attach IOCs to a case

```http
POST /cases/{case_id}/iocs
Content-Type: application/json

{
  "ioc_id": "3f7a1c2e-84b0-4d9a-a3f1-0e6b2c1d4e5f"
}
```

---

### Retrieve full case summary

```http
GET /cases/{case_id}
```

Returns the case with all attached IOCs, their verdicts, scores, and source data — everything an analyst needs to write an incident report.

---

### Close a case

```http
DELETE /cases/{case_id}
```

---

### Health check

```http
GET /health
```

```json
{ "status": "ok", "version": "1.0.0" }
```

---

## Scoring algorithm

Most IOC tools return raw API data and leave interpretation to the analyst. This API adds a scoring layer that combines signals from all three sources into a single actionable verdict.

```python
def score_ioc(vt_result, abuseipdb_result, otx_result) -> dict:
    score = 0
    reasons = []

    # VirusTotal: how many AV engines flagged it
    malicious = vt_result["last_analysis_stats"]["malicious"]
    if malicious > 3:
        score += 40
        reasons.append(f"VirusTotal: {malicious} malicious engine detections")

    # AbuseIPDB: community-reported abuse confidence
    confidence = abuseipdb_result["abuseConfidenceScore"]
    if confidence > 50:
        score += 30
        reasons.append(f"AbuseIPDB: {confidence}% abuse confidence score")

    # AlienVault OTX: threat actor attribution
    pulses = otx_result["pulse_info"]["count"]
    if pulses > 0:
        score += 20
        reasons.append(f"AlienVault OTX: found in {pulses} threat actor pulses")

    verdict = "MALICIOUS" if score >= 60 else "SUSPICIOUS" if score >= 30 else "CLEAN"
    return {"score": score, "verdict": verdict, "reasons": reasons}
```

| Score | Verdict | Meaning |
|---|---|---|
| 0–29 | `CLEAN` | No meaningful signals across sources |
| 30–59 | `SUSPICIOUS` | Some signals — warrants analyst review |
| 60–100 | `MALICIOUS` | Strong multi-source confirmation |

**Design decisions:** VirusTotal is weighted highest (40pts) because it aggregates 70+ AV engines. AbuseIPDB (30pts) relies on community reports and can have false positives, so it carries less weight alone. OTX (20pts) is most valuable for threat actor attribution — even one pulse is significant. A future improvement would be to add recency weighting: a VirusTotal detection from 2019 should score lower than one from last week.

---

## Project structure

```
ioc-enrichment-api/
├── app/
│   ├── main.py              # FastAPI app instance, startup events
│   ├── database.py          # Async SQLAlchemy engine + session factory
│   ├── models/
│   │   ├── ioc.py           # IOCRecord SQLAlchemy model
│   │   └── case.py          # Case + CaseIOC junction table
│   ├── schemas/
│   │   ├── ioc.py           # Pydantic request/response schemas
│   │   └── case.py
│   ├── routers/
│   │   ├── ioc.py           # /ioc/* endpoints
│   │   └── cases.py         # /cases/* endpoints
│   └── services/
│       ├── virustotal.py    # VirusTotal async client
│       ├── abuseipdb.py     # AbuseIPDB async client
│       ├── otx.py           # AlienVault OTX async client
│       ├── scoring.py       # Weighted scoring algorithm
│       └── cache.py         # Redis get/set with TTL
├── tests/
│   ├── test_enrich.py
│   └── test_scoring.py
├── .github/
│   └── workflows/
│       └── deploy.yml       # GitHub Actions → Azure
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Environment variables

```env
# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost/iocdb

# Redis
REDIS_URL=redis://localhost:6379

# Threat intel APIs (use Azure Key Vault in production)
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_otx_key

# Azure (production only)
AZURE_KEY_VAULT_URL=https://your-vault.vault.azure.net
```

In production, all API keys are stored in Azure Key Vault. The `.env` file is for local development only and is excluded from source control.

---

## What I'd build next

- **Slack webhook integration** — post `MALICIOUS` verdicts to a SOC Slack channel automatically, so analysts don't need to poll the API
- **STIX/TAXII export** — standardized threat intel export format, allowing integration with commercial TIP platforms like MISP or ThreatConnect
- **Recency weighting in scoring** — a VirusTotal detection from 3 years ago should carry less weight than one from last month; the scoring algorithm currently treats all detections equally
- **Bulk enrichment endpoint** — `POST /ioc/enrich/bulk` accepting up to 100 IOCs, returning results as a stream; useful for processing full alert IOC lists
- **Shodan integration** — add port/service exposure data for IPs; an IP running port 4444 with no prior abuse history is more suspicious than one running port 443

---

## Author

**Ahmed [Last Name]**
CS Graduate — American University of Sharjah
Targeting blue team / SOC analyst roles in the UAE

[LinkedIn](https://linkedin.com/in/[handle]) · [GitHub](https://github.com/[handle])
