# Multi-Target Evaluation: Deployment & Execution Guide

This guide documents the exact steps to evaluate Red Sentinel against
**OWASP Juice Shop**, **OWASP WebGoat**, and **OWASP Benchmark**.

> **⚠️ Note:** The actual containers could not be deployed in this environment
> because the Docker daemon is not running (`/var/run/docker.sock` missing).
> Target definitions validated and pipeline confirmed working mechanically
> (all 17 endpoints parsed, runner functions verified). Run the steps below on
> any machine with Docker to execute the full evaluation.

## Prerequisites

- Docker Engine 20.10+ (with `docker compose` plugin)
- Python 3.10+
- Ports free: 3000 (Juice Shop), 8080 (WebGoat), 8443 (Benchmark)

## Step 1: Deploy All Targets

```bash
cd /path/to/xbow

# Start core services + all three real-world targets
docker compose --profile eval up -d juice-shop webgoat owasp-benchmark

# ⏳ Cold start takes 30–60s. Poll until ready:
for port in 3000 8080 8443; do
  until curl -s -o /dev/null -w '%{http_code}' http://localhost:$port/ | grep -q 200; do
    sleep 3
  done
  echo "✅ Port $port ready"
done
```

### Health checks

```bash
curl -s -o /dev/null -w 'Juice Shop: %{http_code}\n' http://localhost:3000/
curl -s -o /dev/null -w 'WebGoat:   %{http_code}\n' http://localhost:8080/WebGoat/login
curl -sk -o /dev/null -w 'Benchmark: %{http_code}\n' https://localhost:8443/benchmark
```

## Step 2: WebGoat Authentication

WebGoat requires a one-time user registration, then the pipeline auto-logs in:

```bash
# WebGoat v8+ (version-dependent — adjust endpoint if using v2024.x)
curl -X POST http://localhost:8080/WebGoat/register \
  -H "Content-Type: application/json" \
  -d '{"username":"guest","password":"guest","matchingPassword":"guest","agree":"agree"}'

# After registration, the runner's attempt_target_auth() handles login
# via POST /WebGoat/login with form-encoded username/password
```

## Step 3: Run Evaluations

### Full runs (all endpoints)

```bash
python3 eval/run.py --target juice-shop --output juice-shop-eval
python3 eval/run.py --target webgoat --output webgoat-eval
python3 eval/run.py --target owasp-benchmark --output benchmark-eval
```

### Quick smoke test (1 endpoint each)

```bash
python3 eval/run.py --target juice-shop --limit 1 --output juice-shop-quick
python3 eval/run.py --target webgoat --limit 1 --output webgoat-quick
python3 eval/run.py --target owasp-benchmark --limit 1 --output benchmark-quick
```

### Custom URL (remote deployment)

```bash
python3 eval/run.py --target juice-shop --target-url http://my-server:3000
```

## Step 4: Generate Reports

```bash
# Per-target metrics
python3 eval/analysis/metrics.py juice-shop-eval
python3 eval/analysis/metrics.py webgoat-eval
python3 eval/analysis/metrics.py benchmark-eval

# Cross-target comparison (auto-discovers all runs)
python3 eval/analysis/cross_target.py

# Detailed markdown + HTML reports
python3 eval/reports/report_md.py juice-shop-eval
python3 eval/reports/report_html.py juice-shop-eval
```

## What Each Target Tests

### Juice Shop — 6 endpoints, all Vuln

| Endpoint | Method | Type | Injection Point |
|----------|--------|------|----------------|
| `/rest/products/search?q=` | GET | Reflected | Search query in HTML |
| `/rest/user/login` | POST | Reflected | Email field in error |
| `/api/Reviews` | POST | **Stored** | Review message |
| `/api/Feedbacks` | POST | **Stored** | Comment field |
| `/` (tracking, `?q=`) | GET | Reflected | URL param |
| `/api/BasketItems` | POST | **Stored** | Product name |

### WebGoat — 5 endpoints (4 Vuln + 1 Safe)

| Endpoint | Type | Expected | Notes |
|----------|------|----------|-------|
| `CrossSiteScripting/attack1` | Reflected XSS | Vuln | QTY1 param in HTML |
| `CrossSiteScripting/attack2` | Stored XSS | Vuln | QTY2 stored in session |
| `CrossSiteScripting/attack3` | DOM XSS | Vuln | Client-side JS handler |
| `CrossSiteScripting/attack4` | XSS+CSRF | Vuln | CSRF protection bypass |
| `SqlInjection/attack5` | SQLi | **Safe** | No XSS reflection |

### OWASP Benchmark — 6 endpoints (3 Vuln + 3 Safe)

| Endpoint | Context | Expected |
|----------|---------|----------|
| `BenchmarkTest00001` | HTML body reflection | Vuln |
| `BenchmarkTest00002` | HTML attribute breakout | Vuln |
| `BenchmarkTest00003` | JS string injection | Vuln |
| `BenchmarkTest01000` | Properly escaped | **Safe** |
| `BenchmarkTest01500` | Sanitized output | **Safe** |
| `BenchmarkTest02000` | text/plain content type | **Safe** |

## Output Structure

Each run produces:
```
eval/archive/<run-id>/
  _meta.json              # Target name, URL, timestamp, args
  manifest_frozen.json    # Frozen endpoint definitions
  summary.json            # Aggregated metrics (TP/FN/TN/FP, precision, recall, F1)
  results/                # Per-endpoint raw results
    <endpoint-name>.json
    raw_responses/
```

Cross-target analysis produces per-run comparison:
```
eval/archive/cross_target_report.json
```

## Known Limitations

1. **PortSwigger skipped** for real-world targets (routing uses
   exploitable-specific paths like `/reflected/body`)
2. **WebGoat lesson versioning** may change endpoint paths between v8 and
   v2024.x — adjust manifest if needed
3. **Stored XSS** on Juice Shop requires valid IDs (productId=1, BasketId=1,
   UserId=1) — reload fresh seed data if ids expire
4. **Benchmark HTTPS** uses a self-signed cert — pipeline sets `tls_verify: false`
