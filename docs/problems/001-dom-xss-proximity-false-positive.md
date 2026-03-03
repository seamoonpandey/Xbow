# PROBLEM-001: DOM XSS Proximity-Based False Positive

## Summary

The DOM XSS scanner reported false positives by matching sinks and sources based on line proximity (±5 lines) without verifying actual data flow between them.

## Discovery

**Date:** March 3, 2026
**How:** Manual testing against `https://alf.nu/alert1` — a known XSS challenge site. The scanner reported a high-severity DOM XSS vulnerability that did not exist.

**Reported finding:**
```
Vulnerability: DOM-XSS: document.write <- localStorage.
Type: dom_xss
Severity: high
Confidence: medium (proximity)
```

## What Existed Before

The `_trace_data_flow()` function in `dom_xss_scanner.py` had three analysis levels:

```python
# Level 1: Direct — tainted source on same line as sink (high confidence)
# Level 2: Variable tracing — source assigned to var within ±15 lines (medium)
# Level 3: Proximity fallback — source within ±5 lines (low confidence) ← PROBLEM
```

Level 3 was the problem. The original code:

```python
# --- level 3: proximity fallback (±5 lines) ---
prox_start = max(0, sink_line_idx - 5)
prox_end = min(len(lines), sink_line_idx + 6)

for i in range(prox_start, prox_end):
    if i == sink_line_idx:
        continue
    src = TAINTED_PATTERN.search(check_line)
    if src:
        return True, src.group(0), "low"  # ← reported as finding!
```

This meant: if **any** tainted source keyword appeared within 5 lines of **any** sink keyword, a finding was emitted — regardless of whether there was any data flow between them.

### The Real-World Trigger

The alf.nu/alert1 page contains a fetch polyfill with this structure:

```javascript
// Line N:   window.fetch || document.write('<script src=/s/fetch100.js></script>');
// Line N+3: var saved = localStorage.getItem('lastChallenge');
```

- **Sink found:** `document.write(` on line N
- **Source found:** `localStorage.` on line N+3
- **Distance:** 3 lines → within the ±5 proximity window
- **Conclusion:** "DOM XSS!" — **wrong**, because `document.write` has a static string argument and `localStorage` is used independently

## Root Cause

**Pattern matching was used as a proxy for data-flow analysis.** The assumption "if a source and sink appear close together, they're probably connected" is fundamentally flawed because:

1. Minified/bundled JS often places unrelated code on adjacent lines
2. Feature-detection code (typeof checks, polyfills) uses source keywords without actually reading user data
3. Static string arguments to sinks are safe regardless of what's nearby

The three problems were actually independent issues that compounded:
- Proximity matching without data flow → **this problem (001)**
- `location` pattern matching sources as sinks → **problem 002**
- Static arg check not catching concatenation → **problem 003**

## Solution

Changed Level 3 from "report as finding" to "log for debugging only":

```python
# --- level 3: proximity fallback (±3 lines, strict) ---
# tightened from ±5 to ±3
prox_start = max(0, sink_line_idx - 3)
prox_end = min(len(lines), sink_line_idx + 4)

for i in range(prox_start, prox_end):
    if i == sink_line_idx:
        continue
    check_line = lines[i]
    if _is_comment_line(check_line):
        continue
    src = TAINTED_PATTERN.search(check_line)
    if not src:
        continue
    if _is_source_in_string_context(check_line):
        continue
    # proximity source found but no proven data flow — low confidence
    # we do NOT report this as a finding (too high FP rate)
    # only log it for debugging
    logger.debug(
        f"proximity source {src.group(0)} near sink {sink_name} "
        f"at line {sink_line_idx + 1}, but no data-flow link — skipping"
    )

return False, "", ""
```

Additionally, changed `_scan_single_script()` to only create findings when a tainted source is confirmed:

```python
# Before: always created a finding, even without source
findings.append(DomXssFinding(..., has_tainted_source=has_source, ...))

# After: skip entirely if no source confirmed
if not has_source:
    continue
findings.append(DomXssFinding(..., has_tainted_source=True, ...))
```

## Verification

6 test cases, all passing:

| # | Scenario | Expected | Result |
|---|----------|----------|--------|
| 1 | Static string arg (alf.nu polyfill) | 0 findings | ✅ PASS |
| 2 | Variable tracing (`var x = location.hash; el.innerHTML = x`) | 1 finding | ✅ PASS |
| 3 | Concatenated sink (`document.write('<h1>' + q)`) | 1 finding | ✅ PASS |
| 4 | No tainted source (purely static) | 0 findings | ✅ PASS |
| 5 | Direct source in sink (`el.innerHTML = location.hash`) | 1 finding | ✅ PASS |
| 6 | Feature detection (`typeof localStorage`) | 0 findings | ✅ PASS |

## Pattern / Lesson

> **Never use proximity as a substitute for data-flow analysis in static analysis tools.**
>
> Proximity heuristics seem "good enough" during development but produce false positives at scale. The correct approach is:
> 1. **Direct match** — source literally inside the sink expression (high confidence)
> 2. **Variable tracing** — source assigned to a variable that appears in the sink (medium confidence)
> 3. **No match** — log for debugging, do NOT report
>
> This is the classic precision/recall tradeoff: it's better to miss a real vulnerability (false negative) than to report a non-existent one (false positive), because false positives erode user trust and waste triage time.

## Related

- [002 — Location sink pattern too broad](002-location-sink-pattern-overbroad.md)
- [003 — Static arg check bypassed by concatenation](003-static-arg-concat-bypass.md)
