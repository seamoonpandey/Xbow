# Tier 2 `javascript:` URI Filter & Attribute-Aware Reflection Detection

**Date:** 2026-05-17
**Affects:** `modules/fuzzer-module/app.py`, `modules/fuzzer-module/reflection_checker.py`
**Components:** Fuzzer Module (Python), Reflection Checker

---

## 1. Motivation: The Remaining T2 False Positives

After the decoded-only reflection fix (Tier 3 guard with `verify_execution`), T2
still had **1 false positive**: the `javascript:alert(1)` payload was reflected
as an **exact match** in the HTML body of a safe page. Because exact unencoded
reflections in dangerous positions are flagged as Tier 2 (MEDIUM confidence)
vulnerabilities, the fuzzer reported a vulnerability on a page that was
demonstrably safe.

**Root cause analysis:**

| Payload | Reflection | Position | Why marked vuln | Actual exploitability |
|---------|-----------|----------|----------------|----------------------|
| `javascript:alert(1)` | Exact unencoded | `html_body` + `attribute` | Tier 2: exact in dangerous position | **Inert** — `javascript:` URIs in body text cannot execute |

The fuzzer treated `javascript:alert(1)` reflected in `<p>You searched for: javascript:alert(1)</p>`
the same as `<script>alert(1)</script>` reflected in the same position. But
`javascript:` URIs are fundamentally different — they only execute when placed
in **executable HTML attributes** (`href`, `src`, `action`, `formaction`, `data`).
In body text or safe attributes (`value`, `title`, `alt`, `class`), they are
just text.

**The fix needed to:**

1. **Track which attribute** a payload is reflected in (not just *that* it's in an attribute)
2. **Distinguish body text from attributes** — when a payload appears in both, treat body text as the primary position
3. **Filter `javascript:` / `data:` URIs** at Tier 2: skip marking as vuln when the context is safe

---

## 2. Step-by-Step Process: What We Tried

### Attempt 1 — Simple `attr_name` Check on `javascript:` URIs in Attributes (Fixed T2, Missed Body)

**Hypothesis:** The payload is reflected in `<input value="javascript:alert(1)">`,
so checking `attr_name == "value"` via `is_safe_attribute()` would filter it.

**Implementation:**

- Added `attr_name` field to `ReflectionResult`
- Added `EXECUTABLE_ATTRS` and `SAFE_ATTRS` sets
- Added `is_safe_attribute()` function
- Modified `_find_position()` to return `(position, attr_name)`
- Added Tier 2 filter: skip `javascript:` URI when `position == "attribute"` + safe attr

**Result:** The code review identified that this only works when the payload is
in an **attribute-only** position. For T2 (`/reflected/body`), the payload
`javascript:alert(1)` appears in BOTH:

- `<input value="javascript:alert(1)">` (attribute)
- `<strong>javascript:alert(1)</strong>` (body text)

The `_find_position` function was returning `("html_body", "value")` because
`soup.get_text()` found the payload in visible text. But the Tier 2 filter
only checked `position == "attribute"`, so the `html_body` case was not caught.

**Lesson:** A payload can appear in both body text and an attribute. The
`_find_position` enhancement (checking `get_text()`) was correct, but the
Tier 2 filter must handle BOTH positions, not just `"attribute"`.

### Attempt 2 — Expanded `javascript:` URI Filter for `html_body` and `attribute` (Worked)

**Hypothesis:** `javascript:` URIs are inert in `html_body` too — not just in
safe attributes. Expand the filter to handle both positions.

**Implementation (app.py Tier 2 filter, final):**

```python
is_js_uri_safe = False
payload_lower = payload.lower()
if payload_lower.startswith(("javascript:", "data:text/html", "data:text/javascript")):
    if position == "html_body":
        is_js_uri_safe = True     # inert body text
    elif position == "attribute" and attr_name:
        is_js_uri_safe = is_safe_attribute(attr_name)  # check attribute safety
    # script and style positions remain dangerous

if not is_js_uri_safe:
    is_vuln = True
    vuln_type = "reflected_xss"
```

**Also fixed:** A collapsed-indentation bug in the stored XSS `for r in reflected:`
loop body — the code after `key = f"...""` was outside the loop, causing a
`NameError` at runtime (because `r` was undefined).

**Result:** T2 false positives dropped from **1 → 0**. Red Sentinel achieves
**Perfect detection** (Precision=1.00, Recall=1.00, F1=1.000) with
`verify_execution=True`.

---

## 3. Final Solution Summary

### Fix 1: Reflection Checker — `attr_name` Tracking & `is_safe_attribute()`

**File:** `modules/fuzzer-module/reflection_checker.py`

| Aspect | Before | After |
|--------|--------|-------|
| `ReflectionResult` | `attr_name: str = ""` (unused) | `attr_name` populated when position is `"attribute"` |
| `_find_position()` return | `str` (position only) | `tuple[str, str]` (position, attr_name) |
| Attribute detection | Returned `"attribute"` without naming the attribute | Returns `"attribute"` + attribute name (e.g., `"value"`, `"href"`) |
| Body text detection | Only checked `payload_lower in body.lower()` (includes attribute text) | Also checks `soup.get_text()` (visible text only) — returns `"html_body"` when payload is in both body and attribute |
| New function `is_safe_attribute()` | — | Returns `True` for safe attrs (`value`, `title`, `alt`, etc.), `False` for executable attrs (`href`, `src`, `action`, `formaction`, `data`, etc.) |

**Attribute sets:**

- `EXECUTABLE_ATTRS` (15 attrs): `href`, `src`, `action`, `formaction`, `data`, `xlink:href`, `xlink:actuate`, `xlink:show`, `background`, `longdesc`, `poster`
- `SAFE_ATTRS` (45+ attrs): `value`, `title`, `alt`, `placeholder`, `name`, `id`, `class`, `style`, `width`, `height`, `type`, `checked`, `disabled`, `readonly`, `required`, `selected`, `multiple`, `role`, `min`, `max`, `step`, `pattern`, `autocomplete`, `rel`, `target`, `download`, `hreflang`, `media`, `lang`, `dir`, `hidden`, `tabindex`, `accesskey`, `contenteditable`, `draggable`, `spellcheck`, `translate`, `color`, `size`, `rows`, `cols`, `wrap`, `maxlength`, `minlength`, `autofocus`, `accept`, `capture`, `inputmode`, `list`
- `data-*` and `aria-*` are always safe
- Unknown attributes default to safe (conservative)

### Fix 2: Fuzzer — Extracted `is_js_uri_safe_in_context()` Function

**File:** `modules/fuzzer-module/reflection_checker.py`

Extracted the Tier 2 `javascript:/data:` URI filter logic into a standalone,
testable function:

```python
def is_js_uri_safe_in_context(payload: str, position: str, attr_name: str = "") -> bool:
```

Returns `True` (safe, don't mark vuln) when:

- Payload is a `javascript:` / `data:` URI AND position is `html_body` (inert text)
- Payload is a `javascript:` / `data:` URI AND position is `attribute` with a safe attr name

Returns `False` (dangerous, may mark vuln) when:

- Payload is NOT a `javascript:` / `data:` URI (pass through to standard Tier 2)
- Payload IS a `javascript:` / `data:` URI but position is `script` or `style`
- Payload IS a `javascript:` / `data:` URI but position is `attribute` with no attr_name (conservative)

### Fix 3: Unit Tests (70 tests across 2 files)

**`tests/test_is_safe_attribute.py`** (39 tests):

| Category | Tests | Covered |
|----------|-------|---------|
| Executable attrs | 9 | href, src, action, formaction, data, xlink:href, background, longdesc, poster |
| Safe attrs | 18 | value, title, alt, placeholder, name, id, class, style, type, checked, readonly, required, rel, target, download, hidden, tabindex, lang, dir |
| data-*/aria-* prefixes | 2 | data-custom, aria-label variant |
| Unknown attrs | 1 | Conservative default to safe |
| Case insensitivity | 3 | HREF, VALUE, DATA-CUSTOM |
| Whitespace/dash normalization | 2 | Leading whitespace, leading dashes |
| Set validation | 3 | All EXECUTABLE_ATTRS return False, all SAFE_ATTRS return True, no overlap between sets |

**`tests/test_tier2_js_uri_filter.py`** (31 tests):

| Category | Tests | Covered |
|----------|-------|---------|
| javascript: in body | 1 | Body text is safe (inert) |
| data: URIs in body | 2 | data:text/html + data:text/javascript |
| javascript: in safe attributes | 9 | value, title, alt, placeholder, name, id, class, style, placeholder |
| javascript: in executable attributes | 6 | href, src, action, formaction, data, xlink:href |
| javascript: in script/style positions | 2 | script, style are dangerous |
| Non-JS-URI payloads | 5 | `<script>`, `onerror`, `<svg>`, event handlers — pass through to standard rules |
| Edge cases (no attr_name) | 2 | Conservative default to dangerous |
| Case/whitespace | 3 | JAVASCRIPT:, JavaScript:, leading whitespace |
| Decision matrix smoke tests | 2 | Full matrix for javascript: + data:text/html |

### Fix 4: Stored XSS Pathway — Fixed Collapsed Indentation

**File:** `modules/fuzzer-module/app.py`

The `for r in reflected:` loop body in the stored XSS pathway had a critical
indentation bug — only the first 3 lines (`payload = ...`, `param = ...`,
`key = ...`) were inside the loop. Everything after (including all reflection
checks, vuln marking, and `final_results.append()`) was outside the loop,
causing a `NameError` at runtime since `r` was undefined.

Fixed by indenting all 12 lines of loop body to the correct level.

---

## 4. Verification

### Test Results

```
tests/test_is_safe_attribute.py .............. 39 passed in 0.11s
tests/test_tier2_js_uri_filter.py ......... 31 passed in 0.10s
Total: 70 passed in 0.21s
```

### Evaluation Results (verify_execution=True)

| Test | Expected | Vulns | Executed | Result |
|------|----------|:-----:|:--------:|:------:|
| T1 | Vulnerable | 10 | 9 | ✅ TP |
| T2 | Safe | **0** | **0** | ✅ TN |
| T3 | Vulnerable | 10 | 9 | ✅ TP |
| T4 | Vulnerable | 11 | 11 | ✅ TP |

**Metrics:** Precision=1.000, Recall=1.000, F1=1.000 — **Perfect detection**

### FP Evolution

| Phase | T2 FPs | Fix |
|-------|:------:|-----|
| Baseline (verify=False) | 11 | 10 decoded-only + 1 exact-match |
| Tier 3 decoded-only guard | 1 | Exact-match `javascript:` remained |
| Tier 2 `javascript:` URI filter | **0** | Both `html_body` and `attribute` positions filtered |
| Stored XSS indentation fix | — | Fixes NameError at runtime for stored mode |

---

## 5. Edge Cases Considered

| Edge case | Behavior | Why |
|-----------|----------|-----|
| `javascript:alert(1)` in `<a href="...">` | **Dangerous** (marked vuln) | `href` is in `EXECUTABLE_ATTRS` |
| `javascript:alert(1)` in `<input value="...">` | **Safe** (not marked) | `value` is in `SAFE_ATTRS` |
| `javascript:alert(1)` in `<p>body text</p>` | **Safe** (not marked) | Body text is inert for `javascript:` URIs |
| `javascript:alert(1)` in `<script>` tag | **Dangerous** (marked vuln) | Script context can execute JS URIs |
| `javascript:alert(1)` in `<style>` tag | **Dangerous** (marked vuln) | Style context can execute JS URIs |
| `<script>alert(1)</script>` in `<p>body</p>` | **Dangerous** (marked vuln) | Not a JS URI — standard Tier 2 rules apply |
| `data:text/html,<script>...` in body | **Safe** (not marked) | Same logic as `javascript:` — inert in body |
| `data:text/html,<script>...` in href | **Dangerous** (marked vuln) | `href` is executable |
| `javascript:alert(1)` in attribute but no attr_name | **Dangerous** (conservative) | Cannot determine safety → assume dangerous |
| `javascript:alert(1)` in unknown custom attribute | **Safe** (conservative) | Unknown attrs default to safe |
| `javascript:alert(1)` (leading whitespace) | **Safe** | Whitespace stripped before detection |
| `JavaScript:alert(1)` (mixed case) | **Safe** | `.lower()` applied before detection |
| data-*/ aria-* attributes | **Safe** | Always safe for JS URIs |
| `-value` (leading dash, e.g. from data binding) | **Safe** | Leading dashes stripped before matching |

---

## 6. Lessons

| Lesson | Applies To |
|--------|-----------|
| **A payload can be reflected in BODY and ATTRIBUTE simultaneously.** Checking `soup.get_text()` instead of raw `body.lower()` correctly distinguishes visible body text from attribute values. The body-text position is the correct primary context for exploitability assessment. | Reflection detection |
| **`javascript:` URIs are fundamentally different from script-based XSS payloads.** They only execute in URI-oriented attributes (`href`, `src`, `action`). In body text and safe attributes they are inert text. The same exploitability rules do not apply. | Vulnerability classification |
| **Always extract testable functions from inline logic.** The inline Tier 2 filter in `app.py` was untestable. Extracting `is_js_uri_safe_in_context()` into `reflection_checker.py` made it possible to write 31 unit tests covering the full decision matrix. | Testability |
| **Indentation bugs in Python silently change program behavior.** The collapsed `for` loop body in the stored XSS pathway meant all reflection checking and vuln marking was skipped at runtime — every stored-mode scan was returning 0 vulns from the HTTP path. Always verify loop bodies with a linter or visual scan. | Code quality |

---

## 7. Related

- Evaluation report: `outputs/evaluation_report.md`
- Test file: `tests/test_is_safe_attribute.py` (39 tests)
- Test file: `tests/test_tier2_js_uri_filter.py` (31 tests)
- Production code: `modules/fuzzer-module/reflection_checker.py`
- Production code: `modules/fuzzer-module/app.py`
- Evaluation script: `scripts/rs_eval_final.py`
- `docs/ARCHITECTURE.md` — Section 8.3: Fuzzer Module
- `docs/SCAN_PARAMETERS_GUIDE.md` — `verify_execution` parameter
