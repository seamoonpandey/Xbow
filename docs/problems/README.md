# Problems & Solutions Registry

> Engineering problem log for RedSentinel.
> Each file documents one problem: what existed, what broke, root cause, solution, and the pattern learned.

## Index

| # | Problem | Severity | Component | Status | File |
|---|---------|----------|-----------|--------|------|
| 001 | [DOM XSS proximity false positive](001-dom-xss-proximity-false-positive.md) | HIGH | `dom_xss_scanner.py` | ✅ Fixed | 001 |
| 002 | [Location sink pattern too broad](002-location-sink-pattern-overbroad.md) | HIGH | `dom_xss_scanner.py` | ✅ Fixed | 002 |
| 003 | [Static arg check bypassed by concatenation](003-static-arg-concat-bypass.md) | MEDIUM | `dom_xss_scanner.py` | ✅ Fixed | 003 |
| 004 | [XGBoost cold-start with synthetic data](004-xgboost-cold-start.md) | MEDIUM | `xgboost_ranker.py` | ⚠️ Mitigated | 004 |
| 005 | [Cross-module Python path resolution](005-cross-module-path-resolution.md) | MEDIUM | `ai/training/` | ✅ Fixed | 005 |
| 006 | [Regex escape error in WAF patterns](006-regex-escape-error-waf.md) | LOW | `generate_ranker_data.py` | ✅ Fixed | 006 |
| 007 | [Schema metadata gap across service boundary](007-schema-metadata-gap.md) | MEDIUM | `schemas.py`, TS interfaces | ✅ Fixed | 007 |
| 008 | [Payload bank knowledge gap](008-payload-bank-coverage-gap.md) | MEDIUM | `dataset/` | ✅ Fixed | 008 |
| 009 | [In-memory scan storage — no persistence](009-in-memory-scan-storage.md) | HIGH | `scan.service.ts` | 🔴 Open | 009 |

## How to Use This Registry

1. **Before starting a fix:** Read similar past problems to avoid repeating mistakes
2. **After fixing a bug:** Create a new entry using the template below
3. **During code review:** Reference problem IDs to explain why code looks the way it does

## Template

```markdown
# PROBLEM-NNN: <Title>

## Summary
One-sentence description.

## Discovery
How and when the problem was found.

## What Existed Before
Code/architecture that contained the bug.

## Root Cause
Why the problem happened — the real reason, not the symptom.

## Solution
What was changed, with code diffs.

## Verification
How we confirmed the fix works.

## Pattern / Lesson
The reusable engineering insight.
```
