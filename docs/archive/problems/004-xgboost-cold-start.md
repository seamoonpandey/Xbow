# PROBLEM-004: XGBoost Cold-Start with Synthetic Data

## Summary

The XGBoost payload ranker was bootstrapped with purely synthetic training data, producing a model with only 60% accuracy and 0.63 AUC — essentially near random for a binary classifier. The model provides ranking but its signal is weak.

## Discovery

**Date:** March 3, 2026
**How:** After training the initial XGBoost model on 5,000 synthetic samples, the evaluation metrics showed performance barely above baseline:

```
Accuracy:  60.67%
AUC:       0.6343
F1:        0.6223
Precision: 66.4%
Recall:    58.6%
```

For binary classification, 50% is random chance. 60% means the model is only marginally useful.

## What Existed Before

No ML ranker existed. Payloads were ranked by a heuristic scoring function:

```python
def rank_payloads(payloads, context, waf, allowed_chars):
    """5-component weighted score: context_match + technique + allowed_chars + waf_bypass + length"""
    for p in payloads:
        score = 0.0
        if p['context'] == context: score += 0.3
        if p.get('waf_bypass'): score += 0.2
        # ... etc
```

The heuristic was deterministic and interpretable but couldn't learn from execution results.

## Root Cause

**The chicken-and-egg problem of ML in production systems:**

1. To train a good model, you need real execution data (which payloads succeed/fail against which targets)
2. To get real execution data, you need to run scans
3. To run effective scans, you need a good ranker
4. → circular dependency

The synthetic data generator (`generate_ranker_data.py`) creates samples with simulated outcomes based on hardcoded success rates per context:

```python
CONTEXT_SUCCESS_RATES = {
    "script_injection": 0.35,
    "event_handler": 0.50,
    "attribute_escape": 0.25,
    ...
}
```

These rates are rough estimates, not empirical data. The resulting model learns general patterns ("event handlers succeed more often") but can't learn the nuanced feature interactions that distinguish successful payloads.

## Solution (Mitigation)

This is mitigated, not fully solved:

1. **Auto-fallback**: `xgboost_ranker.py` falls back to the heuristic ranker if the model isn't loaded or XGBoost isn't installed
2. **Training data collection**: `training_collector.py` in the fuzzer module records every payload execution result as JSONL:
   ```python
   {"payload": "...", "context": "event_handler", "waf": "cloudflare",
    "success": true, "reflected": true, "executed": true}
   ```
3. **Retraining pipeline**: `ai/training/train_ranker.py` can retrain from collected data
4. **Heuristic remains primary**: The XGBoost score is blended with heuristic ranking, not used alone

The model will self-improve as real scan data accumulates. After ~1,000 real scans, the model should have enough data to significantly outperform the heuristic.

## Verification

```
Heuristic-only ranking: deterministic, context-match based (no learning)
XGBoost with synthetic: AUC 0.63 (weak but non-random)
XGBoost with real data: TBD — requires production scan data
```

## Pattern / Lesson

> **For ML components in new systems, always build a heuristic fallback first, then layer ML on top.**
>
> The heuristic ranker serves three purposes:
> 1. **Baseline**: Provides acceptable performance before any ML model exists
> 2. **Fallback**: Keeps the system working if the model fails to load
> 3. **Benchmark**: Gives a concrete target for the ML model to beat
>
> The synthetic data bootstrap is a pragmatic approach: it gives the model *something* to start with, even if weak. The key design decision was making the training data collector automatic — every scan improves the model without manual intervention.
>
> **Cold-start is a known ML pattern.** The correct approach is: heuristic → synthetic bootstrap → collect real data → retrain → repeat.

## Status

⚠️ **Mitigated** — model works but is weak. Will self-improve with real scan data. No action required unless accuracy remains below 70% after 500+ real training samples.
