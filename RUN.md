# Red Sentinel — Run Guide

Everything needed to set up and run the project on a fresh Ubuntu/Debian machine.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Node.js** | 22+ | `curl -fsSL https://deb.nodesource.com/setup_22.x \| sudo -E bash - && sudo apt install -y nodejs` |
| **Python** | 3.11+ | `sudo apt install -y python3 python3-pip python3-venv` |
| **PostgreSQL** | 14+ locally / 16 in Docker Compose | `sudo apt install -y postgresql postgresql-contrib` |
| **Redis** | 6.2+ recommended / Redis 7 in Docker Compose | `sudo apt install -y redis-server` |
| **tmux** | any | `sudo apt install -y tmux` |
| **Git** | any | `sudo apt install -y git` |

---

## Quick Start (automated)

```bash
./setup.sh
./start.sh
./stop.sh
```

The remainder of this document explains the manual service-by-service workflow.

---

## Step-by-Step Manual Setup

### 1. Clone the repo

```bash
git clone <your-repo-url> red-sentinel
cd red-sentinel
```

### 2. System packages

```bash
sudo apt update
sudo apt install -y redis-server postgresql postgresql-contrib tmux curl lsof
```

### 3. PostgreSQL — create role and database

```bash
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE ROLE rs WITH LOGIN PASSWORD 'rs';"
sudo -u postgres psql -c "CREATE DATABASE redsentinel OWNER rs;"
psql -h localhost -U rs -d redsentinel -c "SELECT 1;"
```

### 4. Python dependencies

The local scripts use one virtual environment at the project root:

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
```

### 5. Playwright browser

The fuzzer uses Playwright/Chromium for browser verification:

```bash
source venv/bin/activate
python -m playwright install chromium
python -m playwright install-deps chromium
deactivate
```

### 6. Node.js dependencies

```bash
cd core && npm install
cd ../dashboard && npm install
cd ..
```

### 7. Puppeteer browser for PDF report generation

```bash
cd core
npx puppeteer browsers install chrome
cd ..
```

### 8. Build the NestJS core

```bash
cd core
npx nest build
cd ..
```

### 8b. Run database migrations

```bash
cd core
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel npm run migration:run
cd ..
```

The NestJS app is also configured to run pending migrations on startup.

### 9. Environment variables

```bash
cp .env.example .env
```

For local, non-Docker service execution, use localhost service URLs:

```dotenv
NODE_ENV=development
PORT=3000
CORS_ORIGIN=*

CONTEXT_URL=http://localhost:5001
PAYLOAD_GEN_URL=http://localhost:5002
FUZZER_URL=http://localhost:5003

REDIS_HOST=localhost
REDIS_PORT=6379

POSTGRES_USER=rs
POSTGRES_PASSWORD=rs
POSTGRES_DB=redsentinel
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel
```

---

## Running Services Manually

Open separate terminals or tmux panes. Start services in this order.

### Terminal 1 — Redis

```bash
redis-server
```

Verify: `redis-cli ping` → `PONG`

### Terminal 2 — Context Module (port 5001)

```bash
source venv/bin/activate
cd modules/context-module
python app.py
```

Verify: `curl http://localhost:5001/health`

Response shape:

```json
{
  "status": "ok",
  "service": "context-module",
  "ai_model_loaded": true
}
```

`ai_model_loaded` may be false when model artifacts are missing; the classifier code is expected to fall back rather than making the service unavailable.

### Terminal 3 — Payload Generator (port 5002)

```bash
source venv/bin/activate
cd modules/payload-gen-module
DATASET_DIR=../../dataset/splits RANKER_MODEL_DIR=../../model/ranker python app.py
```

Verify: `curl http://localhost:5002/health`

Response shape:

```json
{
  "status": "ok",
  "service": "payload-gen",
  "bank_loaded": true,
  "bank_size": 0,
  "ranker": "heuristic"
}
```

The `ranker` value is `xgboost` when the ranker model is available and `heuristic` otherwise. `/generate` returns 503 if the payload bank is empty or unavailable.

Optional ranker inspection:

```bash
curl http://localhost:5002/ranker/info
```

### Terminal 4 — Fuzzer (port 5003)

```bash
source venv/bin/activate
cd modules/fuzzer-module
python app.py
```

Verify: `curl http://localhost:5003/health`

Response shape:

```json
{
  "status": "ok",
  "service": "fuzzer",
  "training_samples": 0,
  "training_success_rate": 0
}
```

Detailed training-data stats are available from `GET /training/stats`.

### Terminal 5 — Core API (port 3000)

```bash
cd core
npm run start:dev
# or
npx nest build && node dist/main.js
```

Verify:

```bash
curl http://localhost:3000/health
```

Swagger UI is mounted at `http://localhost:3000/docs`.

### Terminal 6 — Dashboard (port 8080)

```bash
cd dashboard
npx next dev -p 8080
```

Open: <http://localhost:8080>

### Terminal 7 (optional) — Vulnerable Test Site (port 9090)

```bash
source venv/bin/activate
cd exploitable
python app.py
```

Open: <http://localhost:9090>

---

## Running a Scan

The scan and report routes are implemented behind the Core JWT guard. In normal use, start scans from the dashboard after logging in. For CLI/API use, include a valid bearer token when your local auth configuration requires it.

```bash
curl -X POST http://localhost:3000/scan \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <JWT>' \
  -d '{
    "url": "http://localhost:9090",
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
  }'
```

Check progress/status:

```bash
curl -H 'Authorization: Bearer <JWT>' http://localhost:3000/scan/<SCAN_ID>
```

Get audit logs:

```bash
curl -H 'Authorization: Bearer <JWT>' http://localhost:3000/scan/<SCAN_ID>/audit
```

### Reports

`GET /scan/<SCAN_ID>/report` returns only a pointer:

```json
{ "reportUrl": "/reports/<SCAN_ID>.html" }
```

Use the report controller endpoints for available formats and file downloads:

```bash
curl -H 'Authorization: Bearer <JWT>' \
  http://localhost:3000/reports/<SCAN_ID>

curl -H 'Authorization: Bearer <JWT>' \
  "http://localhost:3000/reports/<SCAN_ID>/download?format=html"

curl -H 'Authorization: Bearer <JWT>' \
  "http://localhost:3000/reports/<SCAN_ID>/regenerate?formats=html,json,pdf"
```

A download succeeds only when that report format exists or has been regenerated successfully.

---

## Target-Site Authentication During Scanning

Target application login is configured in the scan request body under `options.auth`. This is separate from authentication used to call the RedSentinel API.

```json
{
  "url": "https://target.example",
  "options": {
    "auth": {
      "enabled": true,
      "loginUrl": "https://target.example/login",
      "username": "alice",
      "password": "secret",
      "usernameSelector": "input[name=\"username\"]",
      "passwordSelector": "input[name=\"password\"]",
      "submitSelector": "button[type=\"submit\"]",
      "postLoginWaitMs": 3000,
      "successUrlContains": "/dashboard"
    }
  }
}
```

When login succeeds, Core captures cookies/storage state and passes the authenticated session into crawling, context probing, and fuzzing where supported by the bridge clients. If login fails, the current processor logs the failure and continues unauthenticated.

---

## Port Summary

| Service | Port | Tech |
|---------|------|------|
| Redis | 6379 | Redis |
| PostgreSQL | 5432 | PostgreSQL |
| Context Analyzer | 5001 | Python / FastAPI |
| Payload Generator | 5002 | Python / FastAPI |
| Fuzzer | 5003 | Python / FastAPI / Playwright |
| Core API | 3000 | Node.js / NestJS |
| Dashboard | 8080 | Node.js / Next.js |
| Vulnerable Test Site | 9090 | Python / Flask |

---

## Docker Runtime Mounts

Docker Compose mounts the following important runtime artifacts:

| Mount | Purpose |
|---|---|
| `./model:/app/model:ro` | Context model/tokenizer/checkpoint metadata. |
| `./dataset/splits:/app/dataset/splits:ro` | Payload bank input for payload-gen. |
| `./model/ranker:/app/model/ranker:ro` | XGBoost ranker artifacts. Missing model falls back to heuristic ranking. |
| `training_data:/app/training_data` | Fuzzer-collected ranker training samples. |
| `reports:/app/reports` | Core-generated report files. |
| `pgdata:/var/lib/postgresql/data` | PostgreSQL data. |

---

## Troubleshooting

### Address already in use

```bash
kill $(lsof -t -i:3000)
```

### Playwright browser not found

```bash
python3 -m playwright install chromium
python3 -m playwright install-deps chromium
```

### Context module says `ai_model_loaded` is false

The context model checkpoint or tokenizer may be missing. This does not necessarily prevent the service from running; classifier fallback behavior is used when possible.

### Payload generator has an empty bank

Ensure `DATASET_DIR` points to the generated split files, for example `dataset/splits/`, or use Docker Compose where this directory is mounted into `/app/dataset/splits`.

### Ranker is `heuristic`

The XGBoost ranker artifact was not loaded from `model/ranker/`. The service remains usable and ranks payloads with heuristic scoring.

### PostgreSQL auth failure

```bash
sudo -u postgres psql -c "CREATE ROLE rs WITH LOGIN PASSWORD 'rs';"
sudo -u postgres psql -c "CREATE DATABASE redsentinel OWNER rs;"
```

---

## Scripts Reference

| Script | Description |
|--------|-------------|
| `./setup.sh` | One-time install of packages, dependencies, database setup, browsers, and migrations. |
| `./start.sh` | Launch services in a tmux session. |
| `./start.sh --detach` | Launch services without attaching to tmux. |
| `./stop.sh` | Stop the tmux session and orphaned processes. |
| `cd core && npm run migration:run` | Apply pending database migrations. |
| `cd core && npm run migration:revert` | Roll back the last migration. |
| `cd core && npm run migration:show` | List migrations and status. |
| `cd core && npm run migration:generate -- src/migrations/Name` | Generate a migration from entity changes. |
