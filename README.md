# RedSentinel

AI-assisted XSS vulnerability scanner with a NestJS orchestration core, Python FastAPI analysis services, Redis/BullMQ background scanning, PostgreSQL persistence, and a Next.js dashboard.

This README is the project entry point. Detailed API contracts, scan-option behavior, ML notes, and local setup instructions live in the canonical docs listed in [`docs/README.md`](docs/README.md). Treat application code, DTOs, schemas, Docker Compose, and tests as the source of truth when updating documentation.

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
        └─ Fuzzer module       FastAPI :5003  POST /fuzz
```

Docker Compose also starts Redis on `6379`, PostgreSQL on `5432`, and mounts runtime artifacts for reports, model files, ranker files, dataset splits, and fuzzer training data.

---

## Scan Pipeline

1. **AUTH** — optional target-site login using `options.auth`.
2. **CRAWL** — discover URLs, query params, forms, DOM sinks, and WAF information.
3. **CONTEXT** — call the context module to probe reflection locations and allowed characters.
4. **PAYLOAD-GEN** — select, mutate, obfuscate, and rank payloads. XGBoost is used only when the ranker artifact is available; otherwise heuristic ranking is used.
5. **FUZZ** — test payloads, check reflection, optionally verify execution in a browser, and scan DOM sinks.
6. **REPORT** — score, persist, deduplicate, and generate report files.

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

For manual local setup, see [`RUN.md`](RUN.md).

---

## Core API Surface

`/health` is public. Scan and report routes are implemented behind `JwtAuthGuard`; use the dashboard session/JWT flow or a valid bearer token where configured.

| Method | Endpoint | Implemented behavior |
|---|---|---|
| `POST` | `/scan` | Create a scan, enqueue it, return the scan record. |
| `GET` | `/scan/:id` | Return scan status/record plus persisted vulnerabilities. |
| `GET` | `/scans?page=&limit=` | Return a paginated array of scan records with vulnerabilities. |
| `GET` | `/scan/:id/audit` | Return `{ scanId, logs }` for scan audit entries. |
| `GET` | `/scan/:id/report` | Return `{ reportUrl: "/reports/<id>.html" }` only. This route does not directly download report files. |
| `DELETE` | `/scan/:id` | Cancel an active scan. |
| `DELETE` | `/scans/:id` | Permanently delete one scan and its results. |
| `DELETE` | `/scans` | Delete all scans, results, and reports; returns `{ deleted }`. |
| `GET` | `/reports/:scanId` | Return available generated report formats and download links. |
| `GET` | `/reports/:scanId/download?format=html\|json\|pdf` | Send an existing report file if present. |
| `GET` | `/reports/:scanId/regenerate?formats=html,json,pdf` | Regenerate selected report formats for a completed scan. |
| `GET` | `/health` | Return aggregate health for Python services. |

For request/response examples and microservice contracts, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). For scan-option tuning, see [`docs/SCAN_PARAMETERS_GUIDE.md`](docs/SCAN_PARAMETERS_GUIDE.md).

---

## Minimal `POST /scan` Example

The public Core scan DTO uses camelCase option names.

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
    "singlePage": false
  }
}
```

`options.auth` configures target-application login for scanning protected pages. It is separate from authentication used to call the RedSentinel API.

---

## Runtime Artifacts and Fallbacks

Docker Compose mounts these important paths:

| Path/volume | Used by | Behavior |
|---|---|---|
| `./model:/app/model:ro` | Context module | Health exposes whether the classifier model is loaded. |
| `./dataset/splits:/app/dataset/splits:ro` | Payload-gen | Required for the payload bank; `/generate` returns 503 if the bank is empty. |
| `./model/ranker:/app/model/ranker:ro` | Payload-gen | Missing ranker means heuristic ranking. |
| `training_data:/app/training_data` | Fuzzer | Stores collected ranker training samples. |
| `reports:/app/reports` | Core | Stores generated report files. |

---

## Dataset and ML Notes

The curated payload-bank size is **59,122** (proven by `scripts/dataset_stats.py` Section 11). Current dataset sources are AwesomeXSS, PayloadsAllTheThings, XSSGAI, and PortSwigger cheat-sheet content.

Run `make dataset-report` to generate the authoritative statistics report (12 sections covering family balance, encoding, coverage analysis) and a reproducible `dataset/dataset_manifest.json` with SHA-256 checksums and row counts.

Runtime reflection contexts, training labels, and vulnerability/finding labels are separate. Do not describe the project as having one universal six-class taxonomy.

See [`docs/ML_GUIDE.md`](docs/ML_GUIDE.md) and [`dataset/README.md`](dataset/README.md) for the canonical details.

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
eval/          Evaluation reports, cross-tool comparisons, and analysis scripts ([index](eval/README.md))
docs/          Canonical docs plus historical archive
```

---

## License

MIT
