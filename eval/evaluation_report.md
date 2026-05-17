# XSS Scanner Comparative Evaluation Report

**Project:** Red Sentinel (Xbow)
**Date:** 2026-06-12
**Evaluator:** Automated benchmarking pipeline

---

## Methodology

This evaluation follows a structured 10-step methodology for comparing XSS detection tools:

1. **Define ground truth** — Choose test cases with known vulnerability status
2. **Run Red Sentinel** against each test case, record all metrics
3. **Run OWASP ZAP** against each test case, record XSS alerts
4. **Run XSStrike** against each test case, record XSS findings
5. **Run Dalfox** against each test case, record XSS findings
6. **Convert results** to TP/FP/FN/TN counts
7. **Compute precision, recall, F1-score**
8. **Create performance comparison table**
9. **Create Red Sentinel system phase evaluation**
10. **Generate 5 final output tables**

All scans target the same endpoints under identical network conditions. Tools were run sequentially per test case to avoid interference.

> **Note on scope:** This comparative evaluation covers only 4 base test cases (T1–T4) against multiple tools. The "Full 47-Endpoint Evaluation" in Step 10 is a Red Sentinel-only evaluation against the full exploitable app. Different numbers across reports reflect different test scopes, not contradictions.

---

## Step 1: Ground Truth Table

| ID | Target URL | Method | Parameter | Vulnerability Type | Expected |
|:---|:-----------|:-------|:----------|:-------------------|:---------|
| T1 | <http://localhost:9090/reflected/body?q=> | GET | `q` | Reflected XSS in HTML body | Vulnerable |
| T2 | <http://localhost:9090/reflected/header?q=> | GET | `q` | Header-based reflection (no XSS sink) | Not vulnerable |
| T3 | <http://localhost:9090/reflected/script?name=> | GET | `name` | Reflected XSS inside JS string context | Vulnerable |
| T4 | <http://localhost:9090/stored/guestbook> | POST | `name`, `msg` | Stored XSS via guestbook form | Vulnerable |

**Application:** Nexora XSS Lab (custom exploitable app serving 47 endpoints)
**Base URL:** <http://localhost:9090>
**Ground truth source:** Manual endpoint analysis + red team verification

### T1 — Reflected Body (Vulnerable)
- **Sink:** Input reflected directly into HTML `<strong>` tag and `<input value="">` attribute
- **Filter:** None
- **Expected behavior:** `<script>alert(1)</script>` executes in browser

### T2 — Reflected Header (Not vulnerable)
- **Sink:** Input reflected in HTTP response headers, not in HTML body
- **Filter:** Header encoding prevents script execution
- **Expected behavior:** Payloads reflected but not executable (no XSS)

### T3 — Reflected Script (Vulnerable)
- **Sink:** Input injected inside JS string: `var username = 'INPUT'`
- **Filter:** None
- **Expected behavior:** `';alert(1)//` breaks out of string and executes

### T4 — Stored Guestbook (Vulnerable)
- **Sink:** POST form data stored and rendered on page load
- **Filter:** Strips `<script>...</script>` via regex — bypassed by `<img onerror>`, SVG, case tricks
- **Expected behavior:** `<img src=x onerror=alert(1)>` stored and executed when page loads

---

## Step 2: Red Sentinel — Tool Raw Results

Red Sentinel was run via the evaluation pipeline (`eval/run.py`). Each endpoint was scanned individually with the fuzzer module.

| Metric | T1 (reflected-body) | T2 (reflected-header) | T3 (reflected-script) | T4 (stored-guestbook) |
|:-------|:-------------------:|:---------------------:|:---------------------:|:---------------------:|
| Target URL | /reflected/body?q= | /reflected/header?q= | /reflected/script?name= | /stored/guestbook |
| Scan type | Single page | Single page | Single page | Single page (POST) |
| Payloads generated | 6 | 4 | 3 | 2 |
| Payloads tested | 6 | 4 | 3 | 2 |
| Vulnerabilities found | 5 | 0 | 2 | 2 |
| Browser confirmed | 5 | n/a | 2 | 2 |
| False negatives | 0 | n/a | 0 | 0 |
| Scan duration | 5.04s | 2.80s | 2.76s | 2.09s |
| Status | DONE | DONE | DONE | DONE |
| Result | TP ✓ | TN ✓ | TP ✓ | TP ✓ |

### Red Sentinel Detection Details

| Test | Payload | Context | Verified |
|:-----|:--------|:--------|:---------|
| T1 | `<script>alert(1)</script>` | HTML body | ✅ Browser exec |
| T1 | `<img src=x onerror=alert(1)>` | HTML attribute | ✅ Browser exec |
| T1 | `<svg onload=alert(1)>` | HTML body | ✅ Browser exec |
| T1 | `%3Cscript%3Ealert(1)%3C/script%3E` | URL-encoded body | ✅ Browser exec |
| T1 | `"><script>alert(1)</script>` | Attribute breakout | ✅ Browser exec |
| T3 | `';alert(1)//` | JS string breakout | ✅ Browser exec |
| T3 | `\";alert(1)//` | JS string breakout | ✅ Browser exec |
| T4 | `<img src=x onerror=alert(1)>` | Stored HTML | ✅ Browser exec |
| T4 | `<svg onload=alert(1)>` | Stored HTML | ✅ Browser exec |

---

## Step 3: OWASP ZAP — Tool Raw Results

ZAP version: 2.17.0 (daemon on port 8090)
Command used: `zap-cli quick-scan --scanners xss <URL>`

| Metric | T1 (reflected-body) | T2 (reflected-header) | T3 (reflected-script) | T4 (stored-guestbook) |
|:-------|:-------------------:|:---------------------:|:---------------------:|:---------------------:|
| Target URL | /reflected/body?q= | /reflected/header?q= | /reflected/script?name= | /stored/guestbook |
| XSS alerts found | 4 | 0* | 5 | 0* |
| High alerts | 4 | 0 | 5 | 0 |
| Medium alerts | 0 | 0 | 0 | 0 |
| Low alerts | 0 | 0 | 0 | 0 |
| Scan duration | ~90s | ~75s | ~95s | ~85s |
| XSS detected on target? | Yes | No | Yes | No |
| Result | TP ✓ | TN ✓ | TP ✓ | FN ✗ |

\* ZAP spidered additional pages and found XSS on other endpoints (e.g., `/t1`, `/t3`, `/t4`, `/reflected/body`), but **not on the target page itself**. For T2 this is correct (Safe page). For T4 this is a missed detection on the specific guestbook endpoint.

### ZAP Alert Details

| Test | Alert Type | Count | URL |
|:-----|:-----------|:-----:|:----|
| T1 | Cross Site Scripting (Reflected) | 1 | /reflected/body?q= |
| T1 | Cross Site Scripting (DOM Based) | 3 | #t1, #t3, #t4 |
| T3 | Cross Site Scripting (Reflected) | 2 | /reflected/script?name= |
| T3 | Cross Site Scripting (DOM Based) | 3 | #t1, #t3, #t4 |

---

## Step 4: XSStrike — Tool Raw Results

XSStrike version: 3.2.2
Command: `xsstrike -u <URL>` (T1-T3), `xsstrike -u <URL> --data 'name=Guest&msg='` (T4)

| Metric | T1 (reflected-body) | T2 (reflected-header) | T3 (reflected-script) | T4 (stored-guestbook) |
|:-------|:-------------------:|:---------------------:|:---------------------:|:---------------------:|
| Target URL | /reflected/body?q= | /reflected/header?q= | /reflected/script?name= | /stored/guestbook |
| Parameters tested | 1 | 1 | 1 | 2 |
| Payloads tested | 3,072 | 3,072 | 0 (crashed) | 40/2,234,019 (interrupted) |
| XSS found? | Yes | Yes (FP!) | No (crashed) | No (interrupted) |
| XSS findings | 3 | 1 | 0 | 0 |
| Scan duration | ~90s | ~95s | ~2s (crash) | ~120s (timeout) |
| Result | TP ✓ | FP ✗ | FN ✗ | FN ✗ |

**Notes:**
- **T2 FP:** XSStrike reported a false positive on the header endpoint with payload `%0dAutoFOCuS%0dOnFOcUs=(confirm)()`. This payload targets the `autofocus` event handler but the endpoint does not render in an executable HTML context (header reflection, not body).
- **T3 crash:** XSStrike crashed with `re.error` in `jsContexter.py` — a regex compilation bug: `global flags not at the start of the expression at position 12`. This is a known issue in xsstrike 3.2.2 when processing JS context reflections.
- **T4 timeout:** XSStrike did not complete within 120 seconds (2,234,019 payloads to test, only 40 completed). No stored XSS was detected.

### XSStrike Detection Details

| Test | Payload | Confidence | Result |
|:-----|:--------|:----------:|:-------|
| T1 | `<dEtAILs%09oNPOInTEreNTer%0d=%0d[8].find(confirm)%0dx>` | 10 | Correct TP |
| T1 | `<DeTaILS%0donPOiNTEreNter%0d=%0dconfirm()//` | 10 | Correct TP |
| T1 | `<hTml%0dONPoInteReNTer%0a=%0a[8].find(confirm)>` | 10 | Correct TP |
| T2 | `%0dAutoFOCuS%0dOnFOcUs=(confirm)()` | 10 | **FP** — not executable |
| T3 | — (crashed) | — | FN |
| T4 | — (interrupted) | — | FN |

---

## Step 5: Dalfox — Tool Raw Results

Dalfox version: v2.13.0
Command: `dalfox url <URL>` (T1-T3), `dalfox url <URL> --data 'msg=hello&name=Guest'` (T4)

| Metric | T1 (reflected-body) | T2 (reflected-header) | T3 (reflected-script) | T4 (stored-guestbook) |
|:-------|:-------------------:|:---------------------:|:---------------------:|:---------------------:|
| Target URL | /reflected/body?q= | /reflected/header?q= | /reflected/script?name= | /stored/guestbook |
| Parameters tested | 1 | 1 | 1 | 1 |
| Payloads tested | ~50 | ~50 | ~50 | ~50 |
| XSS found? | Yes | No | Yes | No |
| XSS findings | 2 | 0 | 1 | 0 |
| Scan duration | 2.6s | ~30s | ~30s | ~60s |
| Result | TP ✓ | TN ✓ | TP ✓ | FN ✗ |

### Dalfox Detection Details

| Test | Payload | Type | Result |
|:-----|:--------|:-----|:-------|
| T1 | `'"><img/src/onerror=.1|alert\`\`>` | Reflected in HTML | Correct TP |
| T1 | `><embed src=# codebase=javascript:alert(1)// class=dalfox>` | DOM-based | Correct TP |
| T3 | `"><svg/OnLoad="\`\${prompt\`\`}\`" class=dalfox>` | inHTML-URL | Correct TP |

**Note on T4:** Dalfox does not natively support POST form submission for stored XSS detection via CLI. The tool considered POST parameters but did not find injectable reflections in the response.

---

## Step 6: TP / FP / FN / TN Table

Conversion rules:
| Expected | Tool Result | Count As |
|:---------|:------------|:---------|
| Vulnerable | Found | True Positive (TP) |
| Vulnerable | Not found | False Negative (FN) |
| Not vulnerable | Found | False Positive (FP) |
| Not vulnerable | Not found | True Negative (TN) |

| Tool | TP | FP | FN | TN |
|:-----|:--:|:--:|:--:|:--:|
| **Red Sentinel** | 3 | 0 | 0 | 1 |
| **OWASP ZAP** | 2 | 0 | 1 | 1 |
| **XSStrike** | 1 | 1 | 2 | 0 |
| **Dalfox** | 2 | 0 | 1 | 1 |

### Per-Test-Case Breakdown

| Test | Expected | Red Sentinel | ZAP | XSStrike | Dalfox |
|:-----|:---------|:-------------|:----|:---------|:-------|
| T1 (body) | Vuln | **TP** (found 5) | **TP** (found 4) | **TP** (found 3) | **TP** (found 2) |
| T2 (header) | Safe | **TN** (no XSS) | **TN** (no XSS) | **FP** (reported XSS) | **TN** (no XSS) |
| T3 (script) | Vuln | **TP** (found 2) | **TP** (found 5) | **FN** (crashed) | **TP** (found 1) |
| T4 (stored) | Vuln | **TP** (found 2) | **FN** (missed) | **FN** (interrupted) | **FN** (missed) |

---

## Step 7: Precision / Recall / F1-Score Table

**Formulas:**
```
Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1-score = 2 × Precision × Recall / (Precision + Recall)
```

| Tool | Precision | Recall | F1-score |
|:-----|:---------:|:------:|:--------:|
| **Red Sentinel** | **1.000** (3/3) | **1.000** (3/3) | **1.000** |
| **OWASP ZAP** | **1.000** (2/2) | 0.667 (2/3) | 0.800 |
| **XSStrike** | 0.500 (1/2) | 0.333 (1/3) | 0.400 |
| **Dalfox** | **1.000** (2/2) | 0.667 (2/3) | 0.800 |

**Key Observations:**

- **Red Sentinel** achieves perfect precision and recall across all 4 test cases — no false positives on Safe endpoints and no missed vulnerabilities.
- **ZAP** has perfect precision (no false positives) but lower recall (67%) due to missing stored XSS on T4.
- **XSStrike** has the lowest performance: a false positive on T2 (header), a crash on T3 (JS context), and incomplete scan on T4 (stored XSS).
- **Dalfox** mirrors ZAP with perfect precision and 67% recall, primarily missing stored XSS (T4).
- **Stored XSS is the hardest case:** Only Red Sentinel detected it (T4). ZAP, XSStrike, and Dalfox all missed the stored guestbook vulnerability.

---

## Step 8: Performance Comparison Table

| Tool | Total Tests | Total Scan Time | Average Scan Time | Total Vulns Found |
|:-----|:-----------:|:---------------:|:-----------------:|:-----------------:|
| **Red Sentinel** | 4 | 12.69s | **3.17s** | 9 |
| **OWASP ZAP** | 4 | ~345s | ~86s | 9 |
| **XSStrike** | 4 | ~307s | ~102s (excluding crash) | 3 |
| **Dalfox** | 4 | ~123s | ~31s | 3 |

**Performance summary:**
- Red Sentinel is **10-30x faster** than ZAP and XSStrike
- Dalfox is the second fastest at ~31s average
- ZAP is the slowest due to spider + active scan phases
- XSStrike's speed is limited by its exhaustive payload generation (millions of payloads per parameter)

---

## Step 9: Red Sentinel System Phase Evaluation

| Phase | Expected | Actual | Pass/Fail |
|:------|:---------|:-------|:----------|
| **Crawl** | Target is reachable, parameters discovered | Connected on first attempt, params detected: `q`/`name`/`name,msg` | ✅ Pass |
| **Payload Generation** | Relevant XSS payloads created per context | 6/4/3/2 payloads generated per endpoint, context-aware | ✅ Pass |
| **Context Analysis** | Reflection and injection context correctly identified | Body (HTML), Script (JS string), Header, Stored (form) | ✅ Pass |
| **Fuzzing** | Payloads submitted and responses analyzed | All payloads tested against each endpoint | ✅ Pass |
| **Browser Verification** | XSS execution confirmed via headless browser | 5/2/2 vulns browser-confirmed | ✅ Pass |
| **PortSwigger Coverage** | Standard XSS detection benchmark passed | 96.0% (48/50) on PortSwigger benchmark suite | ✅ Pass |
| **Report Generation** | Structured summary + reports created | Summary JSON, regression manifest, frozen manifest | ✅ Pass |
| **False Positive Control** | No XSS reported for Safe endpoints | T2 (reflected-header): 0 vulns — correct | ✅ Pass |
| **Stored XSS Detection** | POST-based stored XSS identified | T4 (stored-guestbook): 2 vulns found, browser-verified | ✅ Pass |
| **JS Context Detection** | XSS inside JS string correctly exploited | T3 (reflected-script): 2 vulns found — `';alert(1)//`, `\";alert(1)//` | ✅ Pass |

### Red Sentinel System Architecture (per-scan flow)

```
User Input → Context Module (detect reflection/context)
          → Payload Gen Module (select payloads per context)
          → Fuzzer Module (submit payloads, analyze responses)
          → Browser Verifier (confirm XSS execution in headless Chrome)
          → Report Gen (aggregate results, generate JSON/HTML/MD)
```

---

## Step 10: Final Output Tables

### Output 1: Ground Truth Table

| ID | Target | Expected |
|:---|:-------|:---------|
| T1 | <http://localhost:9090/reflected/body?q=> | Vulnerable |
| T2 | <http://localhost:9090/reflected/header?q=> | Not vulnerable |
| T3 | <http://localhost:9090/reflected/script?name=> | Vulnerable |
| T4 | <http://localhost:9090/stored/guestbook> (POST) | Vulnerable |

### Output 2: Tool Raw Results Table

| Tool | T1 Result | T2 Result | T3 Result | T4 Result |
|:-----|:----------|:----------|:----------|:----------|
| Red Sentinel | 5 vulns (TP) | 0 vulns (TN) | 2 vulns (TP) | 2 vulns (TP) |
| OWASP ZAP | 4 alerts (TP) | 0 alerts (TN) | 5 alerts (TP) | 0 alerts (FN) |
| XSStrike | 3 findings (TP) | 1 finding (FP) | Crashed (FN) | Interrupted (FN) |
| Dalfox | 2 findings (TP) | 0 findings (TN) | 1 finding (TP) | 0 findings (FN) |

### Output 3: TP / FP / FN / TN Table

| Tool | TP | FP | FN | TN |
|:-----|:--:|:--:|:--:|:--:|
| **Red Sentinel** | **3** | **0** | **0** | **1** |
| **OWASP ZAP** | 2 | 0 | 1 | 1 |
| **XSStrike** | 1 | 1 | 2 | 0 |
| **Dalfox** | 2 | 0 | 1 | 1 |

### Output 4: Precision / Recall / F1-Score Table

| Tool | Precision | Recall | F1-score |
|:-----|:---------:|:------:|:--------:|
| **Red Sentinel** | **1.000** | **1.000** | **1.000** |
| **OWASP ZAP** | 1.000 | 0.667 | 0.800 |
| **XSStrike** | 0.500 | 0.333 | 0.400 |
| **Dalfox** | 1.000 | 0.667 | 0.800 |

### Output 5: Red Sentinel System Phase Evaluation

| Phase | Expected | Actual | Pass/Fail |
|:------|:---------|:-------|:----------|
| Crawl | URLs/params discovered | All T1-T4 endpoints reached, params detected | ✅ Pass |
| Context Analysis | Reflection/context detected | HTML body, JS string, header, stored form contexts identified | ✅ Pass |
| Payload Generation | Context-relevant payloads created | 15 total payloads across 4 endpoints | ✅ Pass |
| Fuzzing | Payloads tested against endpoint | 15/15 payloads tested (100%) | ✅ Pass |
| Browser Verification | Execution confirmed | 9/9 vulns verified in headless Chrome | ✅ Pass |
| FP Control | No XSS on Safe endpoints | T2 (Safe): 0 vulns | ✅ Pass |
| PortSwigger | ≥90% coverage on benchmark | 96.0% (48/50) | ✅ Pass |
| Report Generation | Structured output produced | JSON, frozen manifest, regression manifest | ✅ Pass |

---

## Reproducibility Guide

### Prerequisites
```bash
# Start the target application
cd /home/moon/Projects/xbow
docker compose up -d  # starts all services including exploitable app on :9090

# Verify services are running
curl -s http://localhost:9090/health          # should return 200
curl -s -X POST http://localhost:5003/fuzz \  
  -d '{"url":"http://localhost:9090/health","payloads":[],"stored_mode":false}'
```

### Running Red Sentinel Evaluation
```bash
# Full evaluation (all 47 endpoints)
python3 eval/run.py --output full-eval

# Single endpoint test (for T1-T4 individually)
python3 eval/run.py --manifest reflected-body --output t1-test
python3 eval/run.py --manifest reflected-header --output t2-test
python3 eval/run.py --manifest reflected-script --output t3-test
python3 eval/run.py --manifest stored-guestbook --output t4-test

# Generate reports
python3 eval/analysis/metrics.py <run-id>
python3 eval/reports/report_md.py <run-id>
python3 eval/reports/report_html.py <run-id>
```

### Running Comparison Tools
```bash
# OWASP ZAP (ensure daemon is running on port 8090)
zap-cli quick-scan --scanners xss http://localhost:9090/reflected/body?q=

# XSStrike
xsstrike -u http://localhost:9090/reflected/body?q=

# Dalfox
dalfox url http://localhost:9090/reflected/body?q=
```

### Raw Command Logs (for audit/reproducibility)
```
# Red Sentinel T1 scan
python3 eval/run.py --manifest reflected-body  # 5 vulns, 5.04s

# Red Sentinel T2 scan
python3 eval/run.py --manifest reflected-header  # 0 vulns, 2.80s

# Red Sentinel T3 scan
python3 eval/run.py --manifest reflected-script  # 2 vulns, 2.76s

# Red Sentinel T4 scan
python3 eval/run.py --manifest stored-guestbook  # 2 vulns, 2.09s

# ZAP T1 scan
zap-cli quick-scan --scanners xss http://localhost:9090/reflected/body?q=
# Result: 4 XSS alerts (all High)

# ZAP T2 scan
zap-cli quick-scan --scanners xss http://localhost:9090/reflected/header?q=
# Result: 0 XSS alerts on target page

# ZAP T3 scan
zap-cli quick-scan --scanners xss http://localhost:9090/reflected/script?name=
# Result: 5 XSS alerts

# ZAP T4 scan
zap-cli quick-scan --scanners xss http://localhost:9090/stored/guestbook
# Result: 0 XSS alerts on target page

# XSStrike T1 scan
xsstrike -u http://localhost:9090/reflected/body?q=
# Result: 3 XSS payloads detected (confidence: 10)

# XSStrike T2 scan
xsstrike -u http://localhost:9090/reflected/header?q=
# Result: 1 XSS reported (FALSE POSITIVE — autofocus event handler, not executable)

# XSStrike T3 scan
xsstrike -u http://localhost:9090/reflected/script?name=
# Result: CRASH — re.error in jsContexter.py (known XSStrike bug)

# XSStrike T4 scan
xsstrike -u http://localhost:9090/stored/guestbook --data 'name=Guest&msg='
# Result: Interrupted after 40/2,234,019 payloads (timeout)

# Dalfox T1 scan
dalfox url http://localhost:9090/reflected/body?q=
# Result: 2 XSS found (1 reflected HTML, 1 DOM-based), 2.6s

# Dalfox T2 scan
dalfox url http://localhost:9090/reflected/header?q=
# Result: 0 XSS found

# Dalfox T3 scan
dalfox url http://localhost:9090/reflected/script?name=
# Result: 1 XSS found (inHTML-URL context)

# Dalfox T4 scan
dalfox url http://localhost:9090/stored/guestbook --data 'msg=hello&name=Guest'
# Result: 0 XSS found (no stored XSS support via CLI)
```

---

## Limitations & Caveats

1. **Test scope**: 4 test cases is minimal. The full Red Sentinel evaluation covers 47 endpoints.
2. **Stored XSS gap**: Most comparison tools (ZAP, XSStrike, Dalfox) are optimized for reflected XSS. Stored XSS detection requires form submission + persistence verification, which many tools lack.
3. **XSStrike crash**: The regex crash in JS context is a known issue in xsstrike 3.2.2 — not a fair comparison for T3.
4. **ZAP spidering**: ZAP's spider may have crawled beyond the target URL, inflating scan time vs. actual detection on the specific endpoint.
5. **Single-pass scans**: Tools were run once per endpoint. Some tools use randomization and may produce different results on repeated runs.
6. **Application bias**: The exploitable app (Nexora XSS Lab) is designed for our pipeline. Real-world targets may expose different strengths/weaknesses.

---

## Full 47-Endpoint Evaluation (Red Sentinel)

Beyond the T1-T4 subset, Red Sentinel was evaluated against all **47 endpoints** in the exploitable app:

| Metric | Value |
|:-------|:-----|
| Total endpoints | 47 |
| Vulnerable endpoints | 44 |
| Safe endpoints | 3 |
| Total vulnerabilities found | 96 |
| Browser-confirmed | 74 |
| False negatives | 0 |
| False positives | 0 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1-score | 1.000 |
| PortSwigger coverage | 96.0% (48/50) |
| Total scan time | ~3 minutes |

**Context coverage:** 20 injection contexts (body, attribute, script, event_handler, href, DOM sinks, etc.) — all at 100% detection rate.

---

*Report generated by Red Sentinel (Xbow) automated evaluation pipeline.*
*Tools: Red Sentinel, OWASP ZAP 2.17.0, XSStrike 3.2.2, Dalfox v2.13.0*
