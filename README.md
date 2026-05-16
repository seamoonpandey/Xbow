# RedSentinel

AI-assisted XSS vulnerability scanner with a NestJS orchestration core, Python FastAPI analysis services, Redis/BullMQ background scanning, PostgreSQL persistence, and a Next.js dashboard.

This README is intentionally concise. The deeper canonical docs are listed in [`docs/README.md`](docs/README.md). Treat application code, DTOs, schemas, Docker Compose, and tests as the source of truth when updating documentation.

---

## Implemented Architecture

```text
Dashboard (Next.js :8080)
        │ REST / Socket.IO
        ▼
Core API (NestJS :3000)
  ├─ Scan, crawler, queue, report, health, auth, scanner-log modules
  ├─ Redis/BullMQ scan queue
  ├─ PostgreSQL scans/vulns persistence
  └─ HTTP clients to Python services
        │
        ├─ Context module      FastAPI :5001  POST /analyze
        ├─ Payload-gen module  FastAPI :5002  POST /generate, GET /ranker/info
        └─ Fuzzer module       FastAPI :5003  POST /test
```

Docker Compose also starts Redis on `6379`, PostgreSQL on `5432`, and mounts runtime artifacts for reports, model files, ranker files, dataset splits, and fuzzer training data.

---

## Scan Pipeline

1. **AUTH** — optional target-site login using `options.auth`.
2. **CRAWL** — discover URLs, query params, forms, DOM sinks, and WAF information.
3. **CONTEXT** — call the context module to probe reflection locations and allowed characters.
4. **PAYLOAD-GEN** — select, mutate, obfuscate, and rank payloads.
5. **FUZZ** — test payloads, check reflection, optionally verify execution in a browser, and scan DOM sinks.
6. **REPORT** — score, persist, deduplicate, and generate report files.

Payload ranking uses XGBoost when `model/ranker/` contains a usable ranker artifact; otherwise it falls back to heuristic ranking.

---

## Quick Start with Docker Compose

```bash
cp .env.example .env
docker compose up -d

curl http://localhost:3000/health
open http://localhost:8080
```

Primary service ports:

| Service | Port |
|---|---:|
| Core API | 3000 |
| Dashboard | 8080 |
| Context module | 5001 |
| Payload-gen module | 5002 |
| Fuzzer module | 5003 |
| Redis | 6379 |
| PostgreSQL | 5432 |

---

## Core API Surface

`/health` is public. Scan and report routes are implemented behind `JwtAuthGuard`; use the dashboard session/JWT flow or a valid bearer token where configured.

| Method | Endpoint | Implemented behavior |
|---|---|---|
| `POST` | `/scan` | Create a scan, enqueue it, return the scan record. |
| `GET` | `/scan/:id` | Return scan status/record plus persisted vulnerabilities. |
| `GET` | `/scans?page=&limit=` | Return a paginated array of scan records with vulnerabilities. |
| `GET` | `/scan/:id/audit` | Return `{ scanId, logs }` for scan audit entries. |
| `GET` | `/scan/:id/report` | Return `{ reportUrl: "/reports/<id>.html" }` only. This route does not directly download HTML/PDF/JSON. |
| `DELETE` | `/scan/:id` | Cancel an active scan. |
| `DELETE` | `/scans/:id` | Permanently delete one scan and its results. |
| `DELETE` | `/scans` | Delete all scans, results, and reports; returns `{ deleted }`. |
| `GET` | `/reports/:scanId` | Return available generated report formats and download links. |
| `GET` | `/reports/:scanId/download?format=html\|json\|pdf` | Send an existing report file if present. |
| `GET` | `/reports/:scanId/regenerate?formats=html,json,pdf` | Regenerate selected report formats for a completed scan. |
| `GET` | `/health` | Return aggregate health for Python services. |

### POST `/scan` request body

The implemented DTO uses camelCase option names.

```json
{
  "url": "https://target.example",
  "options": {
    "depth": 3,
    "maxParams": 100,
    "verifyExecution": true,
    "wafBypass": true,
    "maxPayloadsPerParam": 50,
    "timeout": 60000,
    "reportFormat": ["html", "json"],
    "singlePage": false,
    "auth": {
      "enabled": false,
      "loginUrl": "https://target.example/login",
      "username": "user",
      "password": "password",
      "usernameSelector": "input[name=\"username\"]",
      "passwordSelector": "input[name=\"password\"]",
      "submitSelector": "button[type=\"submit\"]",
      "postLoginWaitMs": 3000,
      "successUrlContains": "/dashboard"
    }
  }
}
```

`options.auth` is target-application authentication for scanning protected pages. It is separate from authentication used to call the RedSentinel API.

---

## Python Microservice APIs

### Context module `:5001`

- `GET /health` → `{ status, service, ai_model_loaded }`
- `POST /analyze`

Request:

```json
{
  "url": "https://target.example/search?q=test",
  "params": ["q"],
  "waf": "none"
}
```

Response is a direct map of parameter names to context objects:

```json
{
  "q": {
    "reflects_in": "html_body",
    "allowed_chars": ["<", ">", "\""],
    "context_confidence": 0.94
  }
}
```

### Payload-gen module `:5002`

- `GET /health` → includes `bank_loaded`, `bank_size`, and `ranker` (`xgboost` or `heuristic`).
- `GET /ranker/info` → ranker status and feature importance when available.
- `POST /generate`

Request uses the Python shared schema field `max_payloads`:

```json
{
  "contexts": {
    "q": {
      "reflects_in": "html_body",
      "allowed_chars": ["<", ">"],
      "context_confidence": 0.94
    }
  },
  "waf": "none",
  "max_payloads": 50
}
```

Response:

```json
{
  "payloads": [
    {
      "payload": "<img src=x onerror=alert(1)>",
      "target_param": "q",
      "context": "html_body",
      "confidence": 0.91,
      "waf_bypass": false,
      "technique": "original",
      "severity": "medium"
    }
  ]
}
```

### Fuzzer module `:5003`

- `GET /health` → includes fuzzer training sample statistics.
- `GET /training/stats` → detailed training data collection stats.
- `POST /test`

There is no implemented `/fuzz` endpoint.

Request uses the Python shared schema field names:

```json
{
  "url": "https://target.example/search",
  "payloads": [
    {
      "payload": "<img src=x onerror=alert(1)>",
      "target_param": "q",
      "confidence": 0.91,
      "technique": "original",
      "severity": "medium",
      "context": "html_body"
    }
  ],
  "verify_execution": true,
  "timeout": 10000,
  "stored_mode": false,
  "display_url": "",
  "form_method": "GET",
  "form_fields": {},
  "context": "html_body",
  "waf": "none",
  "allowed_chars": ["<", ">"]
}
```

Response:

```json
{
  "results": [
    {
      "payload": "<img src=x onerror=alert(1)>",
      "target_param": "q",
      "reflected": true,
      "executed": true,
      "vuln": true,
      "type": "reflected_xss",
      "evidence": {
        "response_code": 200,
        "reflection_position": "html_body",
        "browser_alert_triggered": true
      }
    }
  ]
}
```

---

## Runtime Artifacts and Fallbacks

Docker Compose mounts these important paths:

| Path/volume | Used by | Behavior |
|---|---|---|
| `./model:/app/model:ro` | Context module | Missing classifier artifacts cause fallback behavior in the classifier. Health exposes `ai_model_loaded`. |
| `./dataset/splits:/app/dataset/splits:ro` | Payload-gen | Payload bank must be available for `/generate`; otherwise it returns 503. |
| `./model/ranker:/app/model/ranker:ro` | Payload-gen | Missing ranker means heuristic ranking. |
| `training_data:/app/training_data` | Fuzzer | Stores collected ranker training samples. |
| `reports:/app/reports` | Core | Stores generated report files. |

---

## Dataset and ML Notes

The curated payload bank is documented as approximately **59K+** payloads unless a script or artifact in the repository proves a more exact count. Current dataset documentation lists AwesomeXSS, PayloadsAllTheThings, XSSGAI, and PortSwigger cheat-sheet content as sources.

Context labels are not a single global six-class taxonomy. Runtime reflection contexts include values such as `html_body`, `attribute`, `js_string`, `js_block`, `url`, and `none`; fuzzer finding/vulnerability labels include values such as `reflected_xss`, `stored_xss`, `dom_xss`, `dom_stored_xss`, `template_injection`, `svg_xss`, and `mutation_xss`.

---

## Testing

The repository includes test scripts for the NestJS core and Python modules, but this README does not claim current pass counts.

```bash
cd core
npm test
npm run test:e2e
npm run test:cov

# From the repository root with Python dependencies installed
pytest tests/modules -v
pytest tests/test_integration.py -v
```

---

## Repository Structure

```text
core/          NestJS API, crawler, queue, reports, health, auth, migrations
dashboard/     Next.js dashboard
modules/       Python FastAPI context, payload-gen, fuzzer, and shared schemas
dataset/       Curated, processed, split, and raw/ignored dataset material
model/         Tokenizer, ranker, small metrics, local/ignored large checkpoints
ai/            Training scripts
tools/         Offline inference and maintenance tools
scripts/       Project automation and smoke tests
tests/         Cross-module Python tests
docs/          Canonical docs plus historical archive
```

---

## License

MIT
