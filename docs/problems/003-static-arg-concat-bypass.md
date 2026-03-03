# PROBLEM-003: Static Argument Check Bypassed by String Concatenation

## Summary

The `_has_static_argument()` function incorrectly classified `document.write('<h1>' + userVar + '</h1>')` as having a "static string argument" because the argument started with a quote character — even though dynamic data was concatenated in.

## Discovery

**Date:** March 3, 2026
**How:** While testing concatenated sinks during the DOM XSS proximity fix (Problem 001), the scanner skipped a vulnerability because the string `+` concatenation wasn't detected:

```javascript
var q = new URLSearchParams(location.search).get('q');
document.write('<h1>' + q + '</h1>');  // ← skipped as "static argument"
```

## What Existed Before

```python
_STATIC_ARG_CALL = re.compile(
    r"""(?:document\.write(?:ln)?|eval|setTimeout|setInterval|new\s+Function"""
    r"""|insertAdjacentHTML)\s*\(\s*(['"`])""",
    re.IGNORECASE,
)
_STATIC_ARG_ASSIGN = re.compile(
    r"""\.(?:innerHTML|outerHTML|src|href)\s*=\s*(['"`])""",
    re.IGNORECASE,
)

def _has_static_argument(sink_name: str, line: str) -> bool:
    if _STATIC_ARG_CALL.search(line):
        return True  # ← BUG: returns True even if '...' + var
    if _STATIC_ARG_ASSIGN.search(line):
        return True
    return False
```

The regex checks "does the argument start with a quote?" but doesn't check whether the quote is the **entire** argument or just the beginning of a concatenation expression.

`document.write('<h1>' + q + '</h1>')` → the regex sees `write('` and concludes "static string" — wrong.

## Root Cause

**The check was syntactically shallow.** It matched the first character of the argument (a quote) without analyzing the full expression. In JavaScript, `'...'` is static but `'...' + var` is dynamic. The `+` operator after a string signals concatenation, which means the overall expression contains dynamic data.

Similarly, template literals like `` `Hello ${name}` `` start with a backtick but contain dynamic interpolation via `${...}`.

## Solution

Added concatenation and template literal detection before the static check:

```python
def _has_static_argument(sink_name: str, line: str) -> bool:
    # Reject if there's string concatenation (dynamic data mixed in)
    if re.search(r"""['"]\s*\+|\+\s*['"]""", line):
        return False
    # Reject if there's template literal interpolation
    if "${" in line:
        return False
    # Then do the original checks
    if _STATIC_ARG_CALL.search(line):
        return True
    if _STATIC_ARG_ASSIGN.search(line):
        return True
    return False
```

The concatenation regex `['"]\s*\+|\+\s*['"]` matches:
- `'...' + var` — quote followed by `+`
- `var + '...'` — `+` followed by quote

## Verification

```
Before: document.write('<h1>' + q + '</h1>') → _has_static_argument = True → SKIPPED
After:  document.write('<h1>' + q + '</h1>') → _has_static_argument = False → ANALYZED

Before: document.write('<script src=...>') → _has_static_argument = True → SKIPPED (correct)
After:  document.write('<script src=...>') → _has_static_argument = True → SKIPPED (correct)
```

## Pattern / Lesson

> **When checking if an expression is "safe" (static/constant), ensure you analyze the full expression — not just its first token.**
>
> A common mistake in static analysis is to look at the type of the first operand and draw conclusions about the whole expression. `'...'` is constant, but `'...' + x` could contain anything. Always check for operators that combine static and dynamic parts: `+` (concatenation), `${}` (template interpolation), `.concat()`, etc.
>
> **General rule:** Safety checks must be conservative — if there's any possibility of dynamic content, the expression is NOT safe.

## Related

- [001 — DOM XSS proximity false positive](001-dom-xss-proximity-false-positive.md) (parent fix)
- [002 — Location sink pattern overbroad](002-location-sink-pattern-overbroad.md) (sibling fix)
