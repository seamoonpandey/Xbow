# Research: Extending Synthetic Context Override to `postMessage` & `localStorage`

**Date:** 2026-03-13
**Affects:** (Research — no code changes yet)
**Components:** Crawler, Scan Orchestrator, Context Module, Fuzzer Module, Browser Verifier

---

## 1. Motivation: The Broader Blind Spot

The `__fragment__` fix ([2026-03-13-fragment-context-and-browser-verifier.md](2026-03-13-fragment-context-and-browser-verifier.md))
identified a **systemic limitation** in the scanner architecture:

> The scanner's entire pipeline is built around **HTTP request → HTTP response →
> reflection analysis** flow. Any parameter consumed client-side without a server
> round-trip is invisible to this model.

`__fragment__` (URL hash) was the first and most common instance. But there are
several other client-side-only data sources that modern single-page applications
commonly use:

| Source | Typical usage | Prevalence | XSS sink severity |
|--------|---------------|-----------|-------------------|
| `location.hash` | Fragment-based routing, tab selectors | Very high | Medium–High |
| `postMessage` | Cross-origin iframe communication, widget SDKs | High (in SaaS/embedded apps) | High–Critical |
| `localStorage` | Client-side state (user prefs, cached data, feature flags) | Very high | Medium–High |
| `sessionStorage` | Transient session state | Moderate | Medium |
| `window.name` | Cross-origin data passing (legacy) | Low | Low–Medium |
| `document.cookie` (read by JS) | Client-side cookie reading | Moderate | Medium |

This document focuses on **`postMessage`** and **`localStorage`** — the two
sources that, like `__fragment__`, are consumed client-side without server
reflection but are far more complex to inject into.

---

## 2. How `__fragment__` Works: The Reference Model

The fragment override is a multi-layer intervention spanning 5 services:

| Layer | File | What it does |
|-------|------|-------------|
| **Discovery** | `core/src/crawler/dom-analyzer.service.ts:85` | Scans scripts for `location.hash`, creates `__fragment__` param with `source: 'fragment'` |
| **Context (fallback)** | `modules/context-module/app.py:107-116` | When no reflection exists, assigns `html_body` + `DEFAULT_FRAGMENT_ALLOWED_CHARS` |
| **Context (override)** | `core/src/queue/scan.processor.ts:700-709` | **Unconditionally** overrides `__fragment__` context to `'attribute'` |
| **Payload injection (HTTP)** | `modules/fuzzer-module/http_sender.py:162-175` | Skips HTTP entirely — returns dummy response because server never sees the hash |
| **Browser verification** | `modules/fuzzer-module/app.py:218-270` | Navigates Playwright to `url#<payload>`, checks for `alert()` dialog **without needing any JS orchestration** |

**The key enabler:** The fragment is **natively part of the URL**. Navigating the
browser to `page#<payload>` automatically passes the value to the page's
`location.hash`, which any inline `<script>` tag reading `location.hash` sees immediately
(synchronously available after navigation). For pages that use the
`hashchange` event (less common), the event fires after the document loads
and may not trigger immediately. **No JavaScript injection or inter-process
communication is needed.**

This is the fundamental difference — and why postMessage and localStorage are
harder problems.

---

## 3. Research: Extending to `postMessage`

### 3.1 Current Detection

The scanner already detects `postMessage` as a DOM sink:

- **`modules/fuzzer-module/dom_xss_scanner.py:94-97`** — Detects
  `.postMessage()` calls, recognizes `addEventListener('message', ...)` and
  `onmessage =` as message handlers
- **`modules/fuzzer-module/dom_xss_scanner.py:143-145`** — Tracks
  `e.data`, `event.data`, `.origin` as tainted data flowing into DOM sinks
- **`core/src/common/utils/severity-scorer.ts:58-59`** — Ranks
  `postMessage`/`e.data` as moderate shareability (severity score 2)

However, current detection is **read-only** — it identifies that a page *has* a
postMessage-based XSS path, but cannot confirm execution because there is no
mechanism to actually *send* a message to the page from the scanner.

### 3.2 The Fundamental Gap

postMessage is **push-based**. To confirm a postMessage-based XSS:

1. **You must be "inside" the page** — postMessage requires calling
   `window.postMessage(payload, targetOrigin)` from the same browsing context
   (or an iframe hosted on the same origin)
2. **The handler must execute** — The message handler (`onmessage`) processes
   the payload string and sinks it into the DOM
3. **Origin checks must pass** — Most real-world handlers validate
   `event.origin` against an allowlist. If the origin doesn't match, the
   payload is silently dropped

### 3.3 Required Infrastructure

| Component | What to build | Effort |
|-----------|--------------|--------|
| **Synthetic param** | New `__postmessage__` param, analogous to `__fragment__` | **Low** (copy pattern from `__fragment__`) |
| **Discovery** | `dom-analyzer.service.ts`: detect `addEventListener('message', fn)` or `window.onmessage = fn` in page scripts | **Medium** (AST pattern matching already exists; just add new pattern) |
| **Context override** | `scan.processor.ts`: unconditional override of `__postmessage__` to `'js_context'` or `'html_body'` (message handlers process string data that flows into JS execution, not HTML attributes) | **Low** (copy `__fragment__` pattern) |
| **Payload bank** | New payload class targeting common message handler patterns | **Medium** (need to research common patterns: JSON.parse sinks, innerHTML sinks, eval sinks) |
| **Browser verifier** | New `verify_postmessage_payloads()` function that: | **High** (significant new Playwright logic) |
| | a) Navigates to the target page normally (no hash injection) | |
| | b) Calls `page.evaluate("window.postMessage(payload, '*')")` | |
| | c) Waits for the handler to process the payload (~800ms) | |
| | d) Checks for `alert()` dialog, DOM mutation, or network request | |
| | e) Also tries calling from a sub-iframe for pages that check `source === window` | |
| **Origin validation** | Mechanism to detect the target origin the page validates against | **High** (static analysis or brute-force `*`, `'/'`, and the page's origin) |

### 3.4 The origin problem (why this is difficult)

Unlike fragments where the value is unconditionally available via
`location.hash`, postMessage handlers **validate the sender's origin**:

```javascript
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://trusted.com') return;    // ← MUST PASS
    if (event.origin !== window.location.origin) return;   // ← Or this
    document.body.innerHTML = event.data;                  // ← Sink
});
```

If the origin check is strict, `page.evaluate("window.postMessage(...)")` will
work because the evaluate context **is** the page's origin (`about:blank` or
the page URL). But if the handler checks `event.source === window.parent` or
`event.source === window.opener`, the evaluate context counts as `window`,
which still passes.

**The bigger risk:** Many postMessage handlers also validate the **message
structure** beyond just the origin — they expect a specific JSON schema:

```javascript
onmessage = function(e) {
    var data = JSON.parse(e.data);
    if (data.type !== 'setHtml') return;   // ← Additional validation
    document.getElementById(data.target).innerHTML = data.html;
};
```

This means payloads must be crafted to match the expected message format, which
requires understanding the application's internal protocol — something a
general-purpose scanner cannot do without application-specific configuration.

### 3.5 Effort Estimate: `postMessage`

| Phase | Effort | Complexity | Risk |
|-------|--------|-----------|------|
| Phase 1: Param discovery + context override | 2 days | Low | Low |
| Phase 2: Payload bank (10–15 common patterns) | 3–5 days | Medium | Medium (false positives from origin validation) |
| Phase 3: Browser verifier with postMessage injection | 5–7 days | High | High (browser automation timing, cross-origin restrictions) |
| Phase 4: Origin-aware filtering | 3–5 days | High | High (application-specific logic) |
| **Total** | **13–19 days** | **High** | **Significant risk of false positives** |

The risk of false positives is high because:
1. Many handlers validate origin — payloads silently dropped → `executed: false`
2. Many handlers expect structured JSON — raw strings won't match
3. Timing-dependent handlers (delayed registration) may not be ready when we
   send the message

### 3.6 Recommendation: `postMessage`

**Defer.** The engineering investment is high, and the success rate is
unpredictable without application-specific knowledge. Consider implementing
only if:

- A specific target application is known to use postMessage with an open origin
  (`origin === '*'` or no check)
- The scanner is being used in a dedicated penetration-testing context where
  the operator can provide the expected message format
- A future enhancement adds a "manual payload template" feature so security
  engineers can define custom messages to test

Consider instead: **passive postMessage detection** (no verification) — flag
the page as "potentially vulnerable to postMessage XSS" with evidence of the
handler, but do not attempt confirmation.

---

## 4. Research: Extending to `localStorage`

### 4.1 Current Detection

The scanner has **no detection** for `localStorage` as an injection vector.

Searching the codebase (`localStorage`, `local_storage`, `getItem`) returns
zero results across the fuzzer, context, and payload-gen modules. The
`dom_xss_scanner.py` AST walker likely traverses `localStorage.getItem()`
calls as string literals, but there is no logic to:
- Tag a parameter as `source: 'localStorage'`
- Emit a synthetic param name
- Route payloads to a browser-only verification path

### 4.2 The Injection Challenge

localStorage is fundamentally different from fragments and postMessage:

| Aspect | Fragment | postMessage | localStorage |
|--------|----------|-------------|-------------|
| **How to inject** | Navigate to `url#payload` | Call `window.postMessage(payload, '*')` | **Cannot inject** — localStorage is persistent and same-origin scoped |
| **Lifecycle** | Per-navigation (ephemeral) | Per-event (ephemeral) | **Persistent across navigations** — even loading a different page on the same origin can read it |
| **State dependency** | None (always passed via hash) | None (always dispatched to handler) | **Must be set before the page loads** — scripts read `localStorage.getItem()` at startup |
| **Origin isolation** | Same-origin only | Cross-origin possible | **Strict same-origin** — cannot be read by a different origin |

**The cold-start problem:** If a page reads `localStorage.getItem('theme')` on
load and uses it to set `document.body.className`, you need to:

1. Set `localStorage.setItem('theme', payload)` **before** the page loads
2. Navigate to the page
3. The page reads the payload from localStorage → sinks it into the DOM
4. The verifier checks for execution

But `localStorage` is **same-origin only** — you cannot set it by navigating to
a different URL with a parameter. You need to:

1. Navigate to the **same origin** first
2. Use `page.evaluate("localStorage.setItem('theme', payload)")` to set the
   poisoned value
3. **Reload** the page so the startup script reads the poisoned value
4. Check for execution

This is a **two-step navigation sequence** per payload (load → set → reload →
check), doubling the browser time.

### 4.3 Required Infrastructure

| Component | What to build | Effort |
|-----------|--------------|--------|
| **Discovery** | `dom-analyzer.service.ts`: detect `localStorage.getItem('X')` or `localStorage['X']` in scripts | **Medium** (AST pattern matching: `CallExpression` with a `MemberExpression` callee `localStorage.getItem` and string argument `'X'` — or `MemberExpression` for bracket notation `localStorage['X']`) |
| **Synthetic param** | New `__localstorage_X__` param (one per storage key detected) | **Low** (generate from AST extraction) |
| **Context override** | `scan.processor.ts`: override `__localstorage_X__` to `'html_body'` or `'attribute'` based on how the value is used | **Low** (copy `__fragment__` pattern) |
| **Browser verifier** | New `verify_localstorage_payloads()` function that: | **High** (significant new logic, 2-step navigation) |
| | a) Navigates to the page's origin | |
| | b) Calls `page.evaluate("localStorage.setItem(key, payload)")` | |
| | c) **Reloads** the page | |
| | d) Waits for execution detection (~1000ms) | |
| | e) **Cleans up** by deleting the poisoned key (`localStorage.removeItem(key)`) | |
| | f) Repeats for each payload | |
| **Cleanup safety** | Ensure poisoned localStorage values are deleted after each test to avoid state pollution between test runs | **Critical** — forgetting cleanup corrupts subsequent tests |

### 4.4 The Persistence Problem

localStorage values **persist** even after the browser tab closes. If the
verifier crashes or the scan is interrupted:

- The poisoned localStorage value remains on the user's machine (in the
  Playwright browser profile)
- Subsequent scans against the same origin will see the poisoned value,
  potentially causing false positives
- Cross-contamination between different payloads within the same scan is also
  possible if cleanup runs in a `finally` block that might not execute

**Mitigation:** Use an isolated browser context (`browser.newContext()`) with
a temporary profile that is discarded after the scan. This ensures all
localStorage is automatically cleaned up when the context is closed.

### 4.5 Effort Estimate: `localStorage`

| Phase | Effort | Complexity | Risk | Runtime cost |
|-------|--------|-----------|------|-------------|
| Phase 1: AST discovery + synthetic param | 2–3 days | Low–Medium | Low | None |
| Phase 2: Context override in scan processor | 1 day | Low | Low | None |
| Phase 3: Browser verifier (set → reload → check → cleanup) | 5–7 days | High | High (timing, race conditions, missed `executed`) | **~2x vs fragment** (2 navigations per payload vs 1) |
| Phase 4: Isolated browser context + cleanup guarantee | 2–3 days | Medium | Critical (state contamination) | Negligible |
| **Total** | **10–14 days** | **Medium–High** | **Significant if cleanup is wrong** | **~35–66s per 50 payloads at concurrency 3** |

**Runtime cost detail:** Each localStorage payload requires two navigations
(load → setItem → reload → check) vs one for fragments. At ~2s per navigation
with concurrency 3, 50 payloads takes ~33s for localStorage vs ~17s for
fragments. This is manageable within the current 150–210s HTTP timeout but
reduces headroom for other tests. If both postMessage and localStorage were
added simultaneously, the combined browser time would risk exceeding the
timeout. Consider increasing the fuzzer timeout or routing localStorage tests
through a separate endpoint.

### 4.6 Recommendation: `localStorage`

**Consider implementing** — but only with strict safety guarantees:

1. **Must use isolated browser contexts** — Each scan gets a fresh browser
   profile that is discarded on completion/failure
2. **Must use `try/finally` for cleanup** — Even if the scan crashes, the
   poisoned key must be removed
3. **Should test against known-clean pages first** — Run a pre-scan that
   navigates to the page without any injection to verify the page's normal
   behavior, then compare with the post-injection state

**Why prioritize localStorage over postMessage:**

| Factor | localStorage | postMessage |
|--------|-------------|-------------|
| Injection success rate | High (no origin checks, no schema validation) | Low (origin + schema checks) |
| False positive risk | Low (you control the value injected) | High (silently dropped messages) |
| Implementation complexity | Medium (2-step nav + cleanup) | High (origin/schema handling) |
| Coverage gain | Many apps store user-controlled settings in localStorage | Fewer apps have exploitable postMessage handlers |
| Persistence risk | Yes (mitigated by isolated contexts) | No (ephemeral) |

localStorage is **more predictable** — you control the value, the page reads
it from a predictable key, and there are no origin or schema checks to bypass.
The main engineering costs are:

1. **Two-step navigation** — ~2x browser time vs fragments (~33s per scan vs ~17s)
2. **Cleanup safety guarantees** — isolated browser contexts, `try/finally` everywhere
3. **Discovery complexity** — extracting the storage key name from AST, not just
detecting `localStorage` usage

---

## 5. Architectural Constraints Summary

### Constraint 1: The "No HTTP Reflection" Problem

**Applies to:** postMessage, localStorage, sessionStorage, window.name

None of these sources reflect in the HTTP response. The context module's
entire approach — send probe markers, analyze response — is inapplicable.

**Mitigation pattern (from `__fragment__`):**
- Override context unconditionally in `scan.processor.ts`
- Assign appropriate context type based on how the source is typically
  consumed (postMessage → `'js_context'` or `'html_body'`,
  localStorage → `'html_body'` or `'attribute'`)

### Constraint 2: The "You Must Be Inside the Page" Problem

**Applies to:** postMessage, localStorage

| Source | How to be "inside" | Works with Playwright? |
|--------|-------------------|----------------------|
| Fragment | URL navigation | ✅ Yes (navigate to `url#payload`) |
| postMessage | `page.evaluate()` | ✅ Yes (same origin context) |
| localStorage | `page.evaluate()` → reload | ✅ Yes (two-step navigation) |

Both are feasible with Playwright's `page.evaluate()` which runs JavaScript
in the page's JavaScript context (same origin, same global scope). The
challenge is **timing** — the value must be set at the right moment.

### Constraint 3: The "Batch Timeout" Constraint

**Applies to:** All

Each additional browser navigation per payload adds ~1–2 seconds. With 50
payloads at concurrency 3, that's ~17–33 seconds per source — still within
the 150–210 second HTTP timeout, but only barely. Adding **two** new sources
(postMessage + localStorage) would add another ~35–66 seconds, potentially
pushing past the timeout.

**Mitigation options:**
1. **Run postMessage and localStorage tests in separate HTTP requests**
   (new `/test/postmessage` and `/test/localstorage` endpoints)
2. **Increase the HTTP timeout for fuzzer requests** (from 210s to 300s+)
3. **Reduce concurrency** to keep total time linear rather than stacking

### Constraint 4: The "State Pollution" Problem

**Applies to:** localStorage, sessionStorage, window.name

Unlike fragments (which are ephemeral per navigation), these sources
**persist state** across navigations and even across separate scan runs
if the same browser profile is reused. This creates non-deterministic test
behavior:

- Scan A poisons `localStorage['theme']` with a payload
- Scan B runs against the same origin and reads the poison → false positive
- Even `window.name` persists across navigations within the same tab

**Solution (already partially in place):** Use isolated browser contexts.
The fuzzer already uses `browser.new_context()` per batch, but does not
enforce clean profile disposal. localStorage integration would require
this to be strict.

---

## 6. Recommendations and Priority

| Source | Priority | Effort | Risk | Recommendation |
|--------|----------|--------|------|---------------|
| `__fragment__` | ✅ Done | — | — | **Already fixed** |
| `localStorage` | **High** | 10–14 days | Medium | **Implement** — highest confidence of success, most predictable |
| `postMessage` | **Low** | 13–19 days | High | **Defer** — high false-positive risk, needs app-specific knowledge |

### Short-term (next sprint): localStorage

1. Add `localStorage.getItem()` AST detection to `dom-analyzer.service.ts`
2. Create `__localstorage_<key>__` synthetic params
3. Add context override in `scan.processor.ts`
4. Implement `verify_localstorage_payloads()` in `browser_verifier.py`
5. Add isolated browser context enforcement
6. Run validation against known pages using localStorage as a DOM input source

### Medium-term: postMessage (passive detection only)

1. Add postMessage handler detection to `dom-analyzer.service.ts`
2. Flag detected handlers in scan results (without active verification)
3. Add a "manual postMessage" input field in the dashboard where security
   engineers can paste a custom message payload for verification

### Long-term: General client-side source framework

Design a generic "Client-Side Data Source" plugin system that handles the
common pattern:

```
discover → create synthetic param → override context →
route to browser-only verification → report results
```

This would make adding new sources (sessionStorage, window.name,
document.cookie) a matter of configuration rather than new code.

---

## 7. Lessons

| Lesson | Applies To |
|--------|-----------|
| **Prioritize sources without opaque validation.** localStorage has no origin check, no schema validation, and no message format requirement — you set the value and the page reads it. postMessage requires passing origin checks, message structure checks, and timing windows. When choosing what to implement next, pick the source with the fewest validation layers. | Feature prioritization |
| **Design cleanup before implementation when dealing with persistent state.** localStorage values survive browser restarts. If the verifier crashes mid-scan, poisoned values persist. Always enforce isolated browser contexts and `try/finally` cleanup before writing a single line of injection logic. The cleanup architecture is not an afterthought — it is the foundation. | Stateful source design |
| **Client-side injection requires doubling the browser time budget.** Every payload for localStorage requires two navigations (load → set → reload → check) vs one for fragments. When estimating scan duration, account for this 2× multiplier — a pattern that will apply to any future source requiring pre-injection state setup (sessionStorage, cookies, IndexedDB). | Browser verification |
| **Passive detection is better than no detection.** For high-complexity sources like postMessage where active verification is impractical, flagging the presence of a message handler in scan results with a "potentially vulnerable" warning still provides value. Users can then manually craft a payload. Partial coverage beats zero coverage. | Detection strategy |

---

## 8. Appendix: Common Sink Patterns

### localStorage sinks

```javascript
// Pattern 1: Direct innerHTML
document.body.innerHTML = localStorage.getItem('userContent');

// Pattern 2: jQuery html()
$('#output').html(localStorage.getItem('template'));

// Pattern 3: Script injection via eval
eval(localStorage.getItem('userScript'));

// Pattern 4: dynamic import
import(localStorage.getItem('modulePath'));
```

### postMessage sinks (with origin check patterns)

```javascript
// Pattern 1: No origin check (high risk)
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
});

// Pattern 2: Loose origin check (medium risk)
window.addEventListener('message', function(e) {
    if (e.origin !== 'https://example.com') return;
    eval(e.data);  // ← Still exploitable if origin passes
});

// Pattern 3: Origin-locked (low risk)
window.addEventListener('message', function(e) {
    if (e.origin !== window.location.origin) return;
    // Safe from cross-origin, but same-origin XSS can still trigger
});

// Pattern 4: Structured data (common in widget SDKs)
window.addEventListener('message', function(e) {
    try {
        var msg = JSON.parse(e.data);
        if (msg.type === 'update') {
            $(msg.selector).html(msg.html);
        }
    } catch(e) {}
});
```

---

## 9. Related

- [2026-03-13-fragment-context-and-browser-verifier.md](2026-03-13-fragment-context-and-browser-verifier.md) — The `__fragment__` fix that established the synthetic override pattern
- `core/src/crawler/dom-analyzer.service.ts` — DOM analyzer with fragment detection
- `modules/fuzzer-module/dom_xss_scanner.py` — DOM XSS scanner with postMessage detection
- `core/src/queue/scan.processor.ts` — Scan orchestrator with context override logic
- `modules/fuzzer-module/app.py` — Fuzzer module entry point with fragment routing
- `modules/fuzzer-module/browser_verifier.py` — Browser verification with Playwright
- `docs/ARCHITECTURE.md` — System architecture documentation
