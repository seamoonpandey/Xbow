# `__fragment__` Context Fix & Browser Verifier Timing Optimization

**Date:** 2026-03-13
**Affects:** `core/src/queue/scan.processor.ts` + `modules/fuzzer-module/browser_verifier.py`
**Components:** Scan Orchestrator (NestJS), Fuzzer Module (Python/Playwright)

---

## 1. Research: The Two Gaps

### Gap A — The `__fragment__` Context Problem

**App feature:** The scanner auto-discovers URL fragment-based XSS by injecting a
synthetic `__fragment__` parameter into the payload pipeline. This works because
many JavaScript apps read `location.hash` and write it into the DOM via
`innerHTML` or jQuery `.html()`.

**App limitation:** The context module (Python DistilBERT) analyzes HTTP
responses to determine where a parameter reflects. But URL fragments are never
sent to the server — they are client-side only. The context module receives an
HTTP response that contains **no reflection evidence** for `__fragment__`,
because the server never saw the hash value.

**Consequence:** The context classifier falls back to its default label:
`html_body`. This is the most common context type and the model's default when
it has insufficient signal. The payload generator then produces `<script>`
payloads designed for raw HTML injection.

**The real-world pattern:** When a JavaScript app does:

```javascript
$('#tabContent').html('<h3>' + location.hash + '</h3>');
```

The fragment value lands **inside an attribute template context** — the
`<h3>` tag wraps it. A payload like `<script>alert(1)</script>` is embedded as:

```html
<h3><script>alert(1)</script></h3>
```

This **does execute** in the above case because `innerHTML`-style sinks parse
HTML. But the more critical pattern — and the one the scanner missed — is when
the fragment is concatenated into an existing tag attribute:

```javascript
$('#tabContent').html('<img src="images/' + location.hash + '">');
```

Here the fragment is inside `src="..."` (attribute context). A `<script>` tag
inside this attribute can never break out — it becomes a string value.
The correct injection is an **attribute-breakout payload** like:

```
1" onerror="alert(1)
```

Resulting in:

```html
<img src="images/1" onerror="alert(1)">
```

**The fundamental issue:** The context module will **never** correctly classify
`__fragment__` because the signal it needs (HTTP response reflection) does not
exist. The `html_body` fallback is a systematic limitation of the probe-based
context detection approach when applied to client-side-only parameters.

### Gap B — The Browser Verifier Timing Problem

**App feature:** The scanner verifies JavaScript execution using a headless
Chromium browser (Playwright). After sending HTTP requests with injected
payloads, the fuzzer navigates the browser to the injected URL and checks
whether an `alert()` dialog fires.

**App limitation:** The verifier used `wait_until="domcontentloaded"` for
navigation, then waited only 300ms before checking the `alert_called` flag.
This is too tight for modern single-page applications where vulnerable DOM
elements are created asynchronously in `window.onload` or `setTimeout`
callbacks.

**The real-world pattern:** Many pages use this pattern:

```javascript
window.onload = function() {
    var tabs = '<img id="tabContent" src="images/' + location.hash + '">';
    document.getElementById('container').innerHTML = tabs;
};
```

The execution timeline:

```
DOMContentLoaded  ────  window.onload  ────  DOM mutation  ────  alert()
      │                  │                     │                  │
     0ms               ~800ms                ~900ms             ~950ms
      │
      └── Original verifier checked here (300ms after DOMContentLoaded)
          → onload hasn't fired → no DOM elements → no alert → false negative
```

The verifier's `_attempt_user_interactions` function tries to force-dispatch
`error` events on `img[onerror]` elements, but if those elements don't exist
yet (because `window.onload` hasn't run), the force-dispatch finds nothing to
trigger.

**The timing tradeoff:** Waiting for the real `load` event via
`wait_for_load_state("load")` is correct but expensive — it waits for all page
resources (images, iframes, analytics scripts, fonts) to fully load. On modern
pages this can take 3–10 seconds per payload, which when multiplied across 50+
payloads causes the fuzzer to hit its HTTP request timeout (150–210 seconds).

---

## 2. Step-by-Step Process: What We Tried

### Attempt 1 — Harder `load` Wait (FAILED)

**Hypothesis:** The original 300ms post-`DOMContentLoaded` wait was simply too
short. Using `wait_for_load_state("load", timeout=5000)` should give
`window.onload` ample time to fire.

**Diff:**
```python
# Before:
await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

# After (attempt 1):
await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
await page.wait_for_load_state("load", timeout=5000)  # ← NEW
```

**Result:** Each payload added up to 5 seconds of waiting for images,
analytics, and third-party scripts to load. With 50+ payloads at concurrency 3,
the total fuzzer phase ballooned past the 150-second HTTP timeout set by the
NestJS fuzzer client (`fuzzer-client.service.ts`). The scan returned 0 vulns
because the fuzzer request timed out before completing.

**Lesson:** Real resource loading is too unpredictable and slow for per-payload
verification. A different approach was needed.

### Attempt 2 — Reduced `networkidle` Wait + Removed Redundant Checks (PARTIALLY WORKED)

**Hypothesis:** Instead of waiting for `load`, use `networkidle` with a short
1.5s cap. Also remove a no-op `wait_for_function` that was always matching
because it included `'script'` in its selector (every HTML page has a script
element).

**Diff:**
```python
# Added networkidle with short timeout:
await page.wait_for_load_state("networkidle", timeout=1500)

# Removed (was always matching due to 'script' in selector):
await page.wait_for_function('img[onerror], svg[onload], script, iframe', timeout=3000)
```

**Result:** The scan no longer timed out, but still found 0 vulns for
`__fragment__`. The `networkidle` was a minor improvement, but the fundamental
problem remained: `window.onload` hadn't fired by the time we checked for
alert execution.

### Attempt 3 — Context Override + Synthetic Load Event (WORKED)

**Hypothesis (Context):** Since the context module will never correctly classify
`__fragment__`, we should unconditionally override its context to `'attribute'`
in the scan processor. This forces the payload generator to produce
attribute-breakout payloads regardless of what DistilBERT returns.

**Hypothesis (Verifier):** Instead of waiting for the real `load` event, we can
dispatch a **synthetic** `load` event programmatically via
`page.evaluate("window.dispatchEvent(new Event('load'))")`. This triggers
`window.onload` handlers in ~200ms (vs 3–10s for the real event), because it
bypasses resource loading entirely.

**Context fix diff (scan.processor.ts):**

Before — only upgraded `__fragment__` from `'none'`:
```typescript
if (paramName === FRAGMENT_PARAM && ctxObj.reflects_in === 'none') {
    ctxObj.reflects_in = 'attribute';
}
```

After — unconditional upgrade:
```typescript
if (paramName === FRAGMENT_PARAM) {
    (ctx as Record<string, unknown>).reflects_in = 'attribute';
    (ctx as Record<string, unknown>).allowed_chars = DEFAULT_FRAGMENT_CHARS;
    (ctx as Record<string, unknown>).context_confidence = 0.85;
}
```

**Verifier timing fix diff (browser_verifier.py):**

```python
# After DOMContentLoaded + networkidle, trigger onload handlers:
await page.evaluate("() => window.dispatchEvent(new Event('load'))")
await page.wait_for_timeout(200)

# Then run user interaction simulation:
await _attempt_user_interactions(page, payload, param)

# Then check for execution (increased from 300ms to 800ms):
await page.wait_for_timeout(800)
```

**Why synthetic events are safe:** `new Event('load')` fires identically to the
real `load` event for all DOM0 (`window.onload = fn`) and DOM2
(`window.addEventListener('load', fn)`) handlers. The only difference is
`event.isTrusted === false` — but virtually no real-world application checks
this flag on `load` event handlers.

**Result:**
- **3 vulns found** (up from 2 before any fixes)
- **`executed: true`** on the new `__fragment__` finding (previously `false`)
- **`browserAlertTriggered: true`** — Playwright confirmed the `alert()` fired
- No timeouts (synthetic event takes ~200ms vs 5s for real load)

---

## 3. Final Solution Summary

### Fix 1: Context Override (scan.processor.ts)

| Aspect | Before | After |
|--------|--------|-------|
| `__fragment__` context | Delegated to DistilBERT → `html_body` | Unconditionally `'attribute'` |
| Confidence for `__fragment__` | DNN confidence (typically 0.5–0.6) | Hardcoded 0.85 |
| Allowed chars | DNN output | `<>"'/=#:;()` — full set |
| Why | Assumed context module could handle it | Context module **cannot** detect fragment reflection by design |
| Result | `<script>` payloads → inside attribute → `executed: false` | Attribute-breakout payloads → `executed: true` |

### Fix 2: Synthetic Load Event (browser_verifier.py)

| Aspect | Before | After |
|--------|--------|-------|
| `window.onload` triggering | None (300ms post-DOMContentLoaded) | Synthetic dispatch + 200ms wait |
| Per-payload time overhead | ~300ms (too early to detect) | ~1000ms (200ms load + 400ms interactions + 400ms final) |
| Worst-case (payload*50@conc3) | ~5s → missed vulns | ~17s → found vulns |
| Edge cases with `setTimeout` in onload | Missed (only 300ms total) | 600ms window after onload fires — covers shorter timeouts |

### Why the Failed Attempt Failed

The first attempt (`wait_for_load_state("load", timeout=5000)`) was correct in
intent but wrong in practice because:

1. **Real page loads are unbounded** — images can take 10s+, scripts inject
   more scripts, analytics beacons hang indefinitely
2. **Per-payload overhead multiplies** — 50 payloads × 5s = 250s of browser
   time, easily exceeding the 150–210s HTTP timeout
3. **The fix was in the wrong layer** — The HTTP timeout in
   `fuzzer-client.service.ts` wraps the entire `/test` batch request. Making
   individual payload verification slower makes the whole batch slower.

The synthetic dispatch approach works because it:
- Decouples the onload trigger from resource loading
- Keeps per-payload overhead deterministic (~200ms)
- Does not affect the HTTP timeout at all

---

## 4. Verification

| Metric | Before (original) | After (both fixes) |
|--------|-------------------|-------------------|
| Total vulns | 2 | 3 |
| `__fragment__` vuln present? | No | Yes (CRITICAL) |
| `executed` on `__fragment__` | N/A | `true` |
| `browserAlertTriggered` on `__fragment__` | N/A | `true` |
| Payload that executed | N/A | `1' onerror='alert(1)` |
| Scan timeout? | No | No |
| False positives? | 0 | 0 |

The scan completed against a real-world single-page application that
reads `location.hash` and injects it into the DOM via `innerHTML` — the exact
pattern that both fixes target:

```javascript
function setTab() {
    var tab = location.hash.substring(1);
    var tabs = '<img id="tabContent" src="images/' + tab + '">';
    document.getElementById('tabContent').innerHTML = tabs;
}
```

This is not an isolated test case — it represents a widespread pattern in
single-page applications. The same approach applies to any page that reads
client-side state (hash, `postMessage`, `localStorage`) and injects it into
the DOM.

---

## 5. App Limitations Discovered

### Design Limitation 1: HTTP Probe-Only Context Detection

**What:** The context module detects reflection context by sending HTTP probes
with markers and analyzing the response. It cannot analyze client-side
JavaScript data flow.

**Impact:** Any parameter that is consumed client-side without being reflected
in the HTTP response (fragments, `postMessage`, `localStorage`, `sessionStorage`,
`window.name`, `document.cookie` read by JS) will have incorrect or missing
context classification.

**Mitigation:** Synthetic context overrides in the scan processor for known
client-side-only parameters (`__fragment__`). This approach should be extended
as new client-side sources are discovered — see the dedicated research entry
for [postMessage and localStorage analysis](2026-03-13-research-postmessage-localstorage.md).

### Design Limitation 2: Load-Event-Dependent DOM

**What:** Many web applications create vulnerable DOM elements asynchronously
in `window.onload`, `DOMContentLoaded`, or `setTimeout` callbacks. The
verifier must wait for these to complete before checking for execution.

**Impact:** The verifier needs to balance between waiting long enough for async
operations and being fast enough to avoid HTTP timeouts.

**Mitigation:** Synthetic event dispatch provides deterministic fast triggering.
For `setTimeout` delays beyond 600ms, the verifier may still miss execution.

### Design Limitation 3: Per-Payload Batch Timeout

**What:** The fuzzer client wraps all payload tests for a URL into a single
HTTP request with a fixed timeout. Individual slow payloads delay the entire
batch.

**Impact:** Any per-payload verification step that takes >2s can cause batch
timeout when multiplied across 50+ payloads.

**Mitigation:** Keep per-payload verification under ~1.5s. Consider streaming
results or per-payload timeouts for future improvement.

---

## 6. Lessons

| Lesson | Applies To |
|--------|-----------|
| **When a signal cannot exist, don't trust an ML model's fallback.** If the parameter never reaches the server (fragment, postMessage, localStorage), the context model's output is noise — override unconditionally rather than trusting the model's default classification. | Context classification |
| **Synthetic DOM events are functionally identical and orders of magnitude faster.** `new Event('load')` triggers all DOM0/DOM2 handlers identically to the real event, but completes in microseconds instead of waiting 3–10s for page resources. The only difference is `isTrusted === false`, which virtually no application checks. | Browser verification |
| **Per-item cost multiplies across batch operations.** A 5s per-payload delay becomes 250s across 50 payloads. When verification steps run inside a batched HTTP request, design them to be deterministic and sub-second. | Fuzzer module design |
| **Document failed approaches alongside successful ones.** Recording *why* a seemingly correct fix failed (real load wait → HTTP timeout) clarifies the constraints the final solution must satisfy and prevents repeating the same mistake in future iterations. | All development |

---

## 7. Related

- [2026-03-13-research-postmessage-localstorage.md](2026-03-13-research-postmessage-localstorage.md) — Research on extending the synthetic override pattern to postMessage and localStorage
- [docs/ARCHITECTURE.md](../ARCHITECTURE.md) — Section 6.4: Fuzzer Module
- [docs/archive/problems/001-dom-xss-proximity-false-positive.md](../archive/problems/001-dom-xss-proximity-false-positive.md) — Similar false-negative fix
- `modules/fuzzer-module/browser_verifier.py` — The verifier implementation
- `core/src/queue/scan.processor.ts` — The orchestrator with context override
- `core/src/modules-bridge/fuzzer-client.service.ts` — HTTP timeout configuration
