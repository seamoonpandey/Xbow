# Understanding Scan Parameters: `maxParams` vs `maxPayloadsPerParam`

## Overview

RedSentinel has two critical parameters that control the scope and depth of a scan:

| Parameter | Default | Range | Purpose |
|-----------|---------|-------|---------|
| **`maxParams`** | 100 | 1-500 | Max # of **different parameters** to discover during crawling |
| **`maxPayloadsPerParam`** | 50 | 1-200 | Max # of **payloads to test** per each discovered parameter |

---

## 1. `maxParams` — Parameter Discovery Limit

### What It Does

Controls **how many unique parameters** the crawler will discover and collect.

### Example

Target: `https://example.com`

**With `maxParams=5`:**
```
Crawler discovers:
  /search?q=...
  /user/profile?id=...
  /posts?category=...
  /api/filter?type=...
  /checkout?code=...
  
Found 5 parameters → STOP (reached limit)
Remaining undiscovered params: /cart?item=... ❌ SKIPPED
```

**With `maxParams=100`:**
```
Crawler discovers:
  /search?q=...
  /user/profile?id=...
  /posts?category=...
  /api/filter?type=...
  /checkout?code=...
  /cart?item=...
  ... (more discovered)
  
Found 20+ parameters → continues until limit or page exhaustion
```

### Impact on Scan

- **Low `maxParams` (5-20):** ⚡ Fast scans, but might miss parameters
- **High `maxParams` (200-500):** 🔍 Comprehensive coverage, but slower crawl phase

### Location in Code

[`core/src/crawler/crawler.service.ts` line 99](../core/src/crawler/crawler.service.ts#L99):

```typescript
while (
  toVisit.length > 0 &&
  paramNames.size < maxParams &&  // ← STOP when limit reached
  visited.size < maxUrls &&
  Date.now() - startedAt < crawlTimeoutMs
)
```

---

## 2. `maxPayloadsPerParam` — Payload Per Parameter Limit

### What It Does

Controls **how many payloads** are tested against each discovered parameter once found.

### Example

After crawler finds parameter `q` in `/search?q=...`:

**With `maxPayloadsPerParam=5`:**
```
Payloads generated for parameter 'q':
  1. <script>alert(1)</script>
  2. <img src=x onerror=alert(1)>
  3. "><script>alert(1)</script>
  4. <svg onload=alert(1)>
  5. ';alert(1);//
  
Remaining payloads: [payload6, payload7, ...] ❌ DISCARDED
Only 5 tested against 'q' parameter
```

**With `maxPayloadsPerParam=50`:**
```
Payloads generated for parameter 'q':
  1-50. [50 unique payloads tested]

More comprehensive testing → Higher chance of finding vulnerability
```

### Impact on Scan

- **Low `maxPayloadsPerParam` (5-10):** ⚡ Fast fuzz phase, but risks missing vulnerabilities
- **High `maxPayloadsPerParam` (100-200):** 🔍 Thorough testing per parameter, but slower

### Location in Code

[`core/src/queue/scan.processor.ts` lines 382-417](../core/src/queue/scan.processor.ts#L382):

```typescript
// Step 1: Generate payloads (limited by maxPayloadsPerParam)
const genResp = await this.payloadClient.generate({
  contexts,
  waf,
  maxPayloads: scan.options.maxPayloadsPerParam ?? 50,  // ← LIMIT REQUEST
});

// Step 2: Deduplicate payloads per parameter
const maxPerParam = scan.options.maxPayloadsPerParam ?? 10;
const perParam = new Map<string, Set<string>>();
const uniquePayloads: typeof payloads = [];

for (const p of payloads) {
  const paramKey = String(p.target_param ?? '');
  if (!perParam.has(paramKey)) perParam.set(paramKey, new Set());
  const seen = perParam.get(paramKey)!;
  
  if (seen.has(p.payload)) continue;              // duplicate
  if (seen.size >= maxPerParam) continue;          // ← CAP PER PARAM
  
  seen.add(p.payload);
  uniquePayloads.push(p);
}
```

---

## How They Work Together

### Scan Pipeline

```
┌─────────────────────────────────────────────┐
│ PHASE 1: CRAWL (maxParams)                  │
├─────────────────────────────────────────────┤
│ Discover unique parameters                  │
│ /search?q=...                               │
│ /user/profile?id=...                        │
│ /posts?author=... (limited by maxParams)    │
│                                              │
│ Result: 50 discovered parameters            │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ PHASE 2: ANALYZE & GENERATE                 │
├─────────────────────────────────────────────┤
│ For EACH discovered parameter:              │
│  - Analyze context (where it reflects)      │
│  - Generate payloads                        │
│                                              │
│ For parameter 'q': Generate 50 payloads     │
│ For parameter 'id': Generate 50 payloads    │
│ For parameter 'author': Generate 50 payloads│
│ (limited by maxPayloadsPerParam)            │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ PHASE 3: FUZZ (test all payloads)           │
├─────────────────────────────────────────────┤
│ Total HTTP requests:                        │
│ 50 parameters × 50 payloads = 2,500 tests  │
└─────────────────────────────────────────────┘
```

---

## Effect on Scan Results

### Scenario 1: Low Parameters, High Payloads

```
maxParams = 10 (only test 10 parameters discovered)
maxPayloadsPerParam = 100 (deeply test each one)

Total Tests: 10 × 100 = 1,000 HTTP requests
Risk: Miss vulnerabilities in undiscovered parameters ❌
```

### Scenario 2: High Parameters, Low Payloads

```
maxParams = 200 (discover many parameters)
maxPayloadsPerParam = 5 (shallow test each one)

Total Tests: 200 × 5 = 1,000 HTTP requests
Risk: Miss vulnerabilities due to insufficient payload diversity ❌
```

### Scenario 3: Balanced (Recommended)

```
maxParams = 100 (good coverage)
maxPayloadsPerParam = 50 (sufficient depth)

Total Tests: 100 × 50 = 5,000 HTTP requests
Result: Good balance between breadth and depth ✅
```

### Scenario 4: Comprehensive (Slow but Thorough)

```
maxParams = 500 (crawl entire site)
maxPayloadsPerParam = 200 (maximum depth)

Total Tests: 500 × 200 = 100,000 HTTP requests
Risk: Very slow scan (could take hours/days)
```

---

## Practical Impact Examples

### Test 2: Under-Reported (10 stored XSS instances, 1 reported)

**Root Cause:** Low `maxPayloadsPerParam` (default 50)

```
Payload generation called with:
  maxPayloads: 50

But parameter 'comment' has multiple variants:
  - Encoded (HTML entities)
  - Double-encoded
  - In different contexts (attribute, body, etc.)
  
With 50 payloads, may only find 1 variant that executes ❌
With 100+ payloads, likely to find all 10 variants ✅
```

### Test 7: Duplicate Reporting (3 findings for 1 vulnerability)

**Contributing Factor:** High `maxPayloadsPerParam`

```
Parameter 'search' is vulnerable

With maxPayloadsPerParam=50:
  - Payload 1 executes → Report (HIGH)
  - Payload 2 executes → Report (HIGH) [DUPLICATE]
  - Payload 3 executes → Report (HIGH) [DUPLICATE]
  
Solution: Deduplication + lower payload limit
```

---

## Recommended Settings

### Quick Scan (Testing/Development)
```
maxParams = 20
maxPayloadsPerParam = 10
Est. Time: 2-5 minutes
Coverage: Low
```

### Standard Scan (Default)
```
maxParams = 100
maxPayloadsPerParam = 50
Est. Time: 10-30 minutes
Coverage: Good
```

### Deep/Comprehensive Scan
```
maxParams = 200
maxPayloadsPerParam = 100
Est. Time: 30-60 minutes
Coverage: Excellent
```

### Full Coverage (Research/Lab)
```
maxParams = 500
maxPayloadsPerParam = 200
Est. Time: 1-4 hours
Coverage: Maximum
```

---

## How to Adjust

### Via API Request

```bash
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "options": {
      "maxParams": 100,
      "maxPayloadsPerParam": 50
    }
  }'
```

### Via Environment Variables

In `.env`:
```bash
DEFAULT_MAX_PARAMS=100
DEFAULT_MAX_PAYLOADS=50
```

### Via Dashboard

(Configure in scan options before starting)

---

## Summary

| Parameter | Controls | Default | Affects |
|-----------|----------|---------|---------|
| **`maxParams`** | # of discovered parameters | 100 | **CRAWL PHASE** — Breadth of scan |
| **`maxPayloadsPerParam`** | # of payloads per param | 50 | **FUZZ PHASE** — Depth of testing |

**Key Insight:** 
- Too many params + too few payloads = miss vulnerabilities
- Too few params + too many payloads = waste resources on incomplete coverage
- **Balance is key** for optimal scan results
