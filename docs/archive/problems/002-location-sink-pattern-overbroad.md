# PROBLEM-002: Location Sink Pattern Too Broad

## Summary

The `location_assign` sink regex `location\s*[=.]` matched tainted **sources** like `location.hash` and `location.search` as if they were dangerous **sinks**, causing phantom findings where `location.hash` was reported as both the source and the sink.

## Discovery

**Date:** March 3, 2026
**How:** While writing verification tests for the DOM XSS proximity fix (Problem 001), a test for variable tracing produced 2 findings instead of 1:

```
Expected: 1 finding (innerHTML <- location.hash)
Actual:   2 findings:
  - innerHTML <- location.hash        ← correct
  - location_assign <- location.hash  ← WRONG — location.hash is a source, not a sink
```

## What Existed Before

```python
"location_assign": {
    "pattern": r"(location\s*[=.]|window\.location\s*=|document\.location\s*=)",
    "severity": "medium",
    "type": "open_redirect",
},
```

The `[=.]` character class matches both:
- `location =` (write — **is** a sink) ✅
- `location.hash` (read — **is** a source, NOT a sink) ❌
- `location.search` (read — source) ❌

The DOM `location` object has dual semantics:
- **Reading** properties (`location.hash`, `location.search`) = **source** of user input
- **Writing** properties (`location.href = x`, `location.assign(x)`) = **sink** that navigates the browser

## Root Cause

The regex used a character class `[=.]` that was too broad — it treated a `.` (property access for reading) identically to `=` (assignment for writing). This is a semantic distinction that a single character class cannot express.

## Solution

Replaced with explicit write-only patterns:

```python
"location_assign": {
    "pattern": (
        r"(?:window\.|document\.)?location\s*="
        r"|(?:window\.|document\.)?location\s*\.\s*(?:href|pathname)\s*="
        r"|(?:window\.|document\.)?location\s*\.\s*(?:assign|replace)\s*\("
    ),
    "severity": "medium",
    "type": "open_redirect",
},
```

**Matches (sinks):** `location =`, `location.href =`, `location.pathname =`, `location.assign()`, `location.replace()`
**Correctly skips (sources):** `location.hash`, `location.search`, `window.location.href` (without `=`)

## Verification

```
Before: var x = location.hash; el.innerHTML = x → 2 findings (1 phantom)
After:  var x = location.hash; el.innerHTML = x → 1 finding (correct)
```

## Pattern / Lesson

> **When building regex for APIs with dual read/write semantics, match the operation explicitly — never wildcard across the read/write boundary.**
>
> In the DOM API, many objects serve as both sources and sinks depending on whether you read or write them: `location`, `document.cookie`, `localStorage`. A regex like `location[=.]` cannot distinguish between these operations. Always enumerate the specific write patterns you want to catch.

## Related

- [001 — DOM XSS proximity false positive](001-dom-xss-proximity-false-positive.md) (discovered together)
- [003 — Static arg concat bypass](003-static-arg-concat-bypass.md) (related scanner fix)
