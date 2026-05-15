# PROBLEM-006: Regex Escape Error in WAF Simulation Patterns

## Summary

The synthetic training data generator used raw regex special characters in WAF block patterns, causing `re.error` when processing certain payloads. Specifically, `on\w+=` was used as a substring match but was passed to `re.search()`, and some payload strings contained regex metacharacters that broke compilation.

## Discovery

**Date:** March 3, 2026
**How:** Running `python ai/training/generate_ranker_data.py` to generate synthetic training samples crashed with:

```
re.error: bad escape \w at position 2
```

The error came from WAF simulation code that checked whether a payload would be blocked.

## What Existed Before

```python
WAF_BLOCKS = {
    "cloudflare": ["<script", "onerror=", "javascript:", "on\\w+="],
    "akamai":     ["<script", "eval(", "document.cookie"],
    ...
}

def _would_waf_block(payload: str, waf: str) -> bool:
    for pattern in WAF_BLOCKS.get(waf, []):
        if re.search(pattern, payload, re.IGNORECASE):  # ← crashes on "on\\w+="
            return True
    return False
```

The `on\\w+=` pattern was intended as a regex `on\w+=` (match event handlers like `onclick=`, `onerror=`), but the inconsistent escaping — combined with mixing regex patterns and literal substrings — made it fragile.

## Root Cause

**Mixing regex patterns with plain substring patterns in the same list, then applying `re.search()` to all of them.** Some entries like `<script` are plain substrings. Others like `on\w+=` are regex patterns. When Python processes the list:

1. `"<script"` → valid regex (matches literal `<script`) ✅
2. `"on\\w+="` in a Python string → becomes `on\w+=` at runtime → valid regex ✅
3. But if someone writes `"on\w+="` (single backslash in source) → Python interprets `\w` as a literal `\w` → still works as regex ✅
4. The real issue: payload strings sometimes contain `(`, `)`, `[`, `]`, etc. that break when the "pattern" itself isn't properly escaped

The confusion between "is this a regex?" and "is this a substring?" made the code brittle.

## Solution

Changed WAF block checking from `re.search()` to plain substring matching for all patterns, and replaced regex patterns with explicit substring lists:

```python
WAF_BLOCKS = {
    "cloudflare": ["<script", "onerror=", "javascript:", "onclick=", "onload=", "onmouseover="],
    "akamai":     ["<script", "eval(", "document.cookie"],
    ...
}

def _would_waf_block(payload: str, waf: str) -> bool:
    lower = payload.lower()
    for pattern in WAF_BLOCKS.get(waf, []):
        if pattern.lower() in lower:  # substring match, not regex
            return True
    return False
```

This is both more robust (no regex compilation errors) and more realistic (most WAFs do substring/signature matching, not regex matching).

## Verification

```bash
python ai/training/generate_ranker_data.py
# → Generated 5000 samples without errors
```

## Pattern / Lesson

> **Never mix regex patterns and plain strings in the same collection. Pick one approach and stick with it.**
>
> If you need both, use explicit types:
> ```python
> blocks = [
>     {"type": "substring", "value": "<script"},
>     {"type": "regex", "value": r"on\w+="},
> ]
> ```
>
> For security tool WAF simulation, plain substring matching is usually more appropriate than regex — it matches how most real WAFs work and avoids the entire class of regex injection/escaping bugs.
