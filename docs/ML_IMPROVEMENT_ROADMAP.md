# ML Improvement Roadmap — RedSentinel v2.0

**Date:** March 6, 2026  
**Status:** Production v1.0 ready, v2.0 planning phase

This document identifies areas where RedSentinel's current heuristic-based or hardcoded logic can be replaced with custom ML models, using only **internal training data** (zero external API costs).

---

## Executive Summary

RedSentinel v1.0 is production-ready, but 5 areas can be significantly improved with lightweight ML models trained on your own collected data:

| Area | Current | Proposed | ROI | Effort |
|------|---------|----------|-----|--------|
| **Mutation XSS Detection** | Regex patterns | DistilBERT classifier | 🔴 High | ⭐ Low |
| **False Positive Filtering** | None | Binary classifier | 🔴 High | ⭐⭐ Medium |
| **Execution Probability** | Always verify in browser | Confidence-based skip | 🟡 Medium | ⭐⭐ Medium |
| **WAF Evasion Strategy** | 8 hardcoded rules | Adaptive recommender | 🟡 Medium | ⭐⭐⭐ High |
| **Payload Ranking** | Context-based | Effectiveness ranker | 🟡 Medium | ⭐⭐ Medium |

---

## 1. MUTATION XSS CLASSIFIER 🔴 HIGHEST PRIORITY

### Current Approach
```python
def detect_advanced_xss_type(payload, position, response_body, is_exact, executed):
    # Regex patterns for templates
    template_patterns = [
        r'\{\{.*?\}\}',          # AngularJS
        r'\$\{.*?\}',             # Jinja
        r'<%.*?%>',               # ERB
        r'\[%.*?%\]',            # Thymeleaf
    ]
    # SVG patterns
    svg_patterns = [r'<svg', r'<SVG', r'onload=', r'onerror=']
    # Decoded-only reflection check
```

**Weaknesses:**
- ❌ Only catches obvious template/SVG syntax
- ❌ Misses browser-specific parsing tricks (namespace tricks, CDATA tricks)
- ❌ Can't adapt to new mXSS vectors discovered after deployment
- ❌ False positives (e.g., `{{` in comments detected as template injection)
- ❌ High false negatives (HTML5 quirks mode bypasses)

### Proposed Solution: DistilBERT Mutation XSS Classifier

**Model Architecture:**
```
Input: [payload_text, response_body_context, reflection_position]
  ↓
DistilBERT encoder (shared with existing context classifier)
  ↓
Classification head: is_mutation_xss (binary)
  ↓
Output: [probability, confidence]
```

**Training Data:**
- Source: `/mutation/innerhtml`, `/mutation/angular`, `/mutation/svg`, `/mutation/srcdoc`, `/mutation/prototype` endpoints
- Labels: `mutation_xss` + negative samples from regular `reflected_xss`
- Target: 500-2000 labeled examples (can collect during v1.0 scans)
- Ground truth: Payload execution confirmed via browser + response analysis

**Expected Improvements:**
- ✅ Recall: 65% → 85%+ (catch more mXSS variants)
- ✅ Precision: 70% → 92%+ (fewer false positives)
- ✅ Adaptive: Learns new bypass patterns from scan results
- ✅ Speed: Same as context classifier (no extra latency)

**Implementation Timeline:**
- Week 1: Collect mutation findings from v1.0 deployments
- Week 2: Label and prepare training data
- Week 3: Fine-tune model, create evaluation benchmark
- Week 4: Integration + A/B test vs regex approach

---

## 2. FALSE POSITIVE FILTER 🔴 CRITICAL IMPACT

### Current Approach
**Problem:** Every reflected payload = potential XSS reported
```
Reflected in HTML body? → Report as reflected_xss
Exact match in dangerous position? → Report as HIGH
```

**Why it fails:**
- Data reflected in `<pre>`, `<textarea>`, comments → reflected but not exploitable
- JSON responses containing user input → reflected but sandboxed
- Markdown escaping → reflected but html-encoded
- Admin-only sections → reflected but attacker can't access
- ~30-50% of findings are false positives in real scans

### Proposed Solution: Real XSS vs Noise Binary Classifier

**Model:**
```
Input: [payload, reflection_context, html_position, response_metadata]
  ↓
DistilBERT + contextual features (position embedding, tag type, etc.)
  ↓
Binary head: is_real_xss (probability)
  ↓
Output: Real XSS vs Noisy Reflection
```

**Training Data:**
- Source: Your historical scan findings + manual review of false positives
- Labels: True XSS (confirmed execution) vs False Positive (no execution)
- Target: 1000-3000 labeled examples per domain
- Ground truth: Browser verification results + manual triage

**Expected Improvements:**
- ✅ Precision: 60-70% → 85%+ (fewer false alerts)
- ✅ Reduced triage burden: Manual review -30%
- ✅ Better prioritization: Real findings ranked higher
- ✅ Higher confidence: Scanner credibility increases

**Integration Point:**
```typescript
// Before reporting a finding
const realXssProb = falsePositiveFilter.classify({
  payload,
  context: reflectionPosition,
  evidence,
});

if (realXssProb < 0.3) {
  logger.debug('Skipping likely false positive');
  return;
}

// Report with confidence score
vuln.confidence = realXssProb;
```

**Implementation Timeline:**
- Week 1: Build feedback loop (users flag false positives)
- Week 2-3: Collect 1000+ labeled examples
- Week 4: Train + evaluate
- Week 5: Beta test with early users
- Week 6: Full rollout with confidence scores

---

## 3. EXECUTION PROBABILITY PREDICTOR 🟡 PERFORMANCE GAIN

### Current Approach
```python
# Every exact match in dangerous position gets browser verification
if is_reflected and is_exact and position in DANGEROUS_POSITIONS:
    browser_results = await verify_payloads(url, payload, timeout=10s)
```

**Cost:**
- Browser verification: 5-15 seconds per payload
- With 50 payloads per param = 250-750 seconds (4-12 minutes per scan)
- Major bottleneck for large scans

**Why it's inefficient:**
- Not all reflected payloads will execute (syntax errors, CSP, browser bugs)
- Some positions are safe even if reflected (comments, within strings)
- Browser verification is expensive; would benefit from early filtering

### Proposed Solution: Execution Probability Ranker

**Model:**
```
Input: [payload_text, browser_context, csp_headers, target_position]
  ↓
LightGBM or shallow neural net (fast inference)
  ↓
Output: execution_probability (0.0-1.0)
```

**Decision Logic:**
```python
exec_prob = model.predict(payload, position, browser)
if exec_prob < 0.2:
    logger.debug('Skip browser verify (low prob)')
    mark_as_reflected_but_unexecuted()
elif exec_prob > 0.8:
    browser_verify()  # Almost certainly will execute
elif 0.2 <= exec_prob <= 0.8:
    browser_verify()  # Worth checking
```

**Training Data:**
- Source: All your verified payloads with browser results
- Labels: `executed=True/False` from Playwright results
- Target: 2000+ examples per context type
- Ground truth: Actual browser execution logs

**Expected Improvements:**
- ✅ Speed: Skip 30-50% of browser verifications
- ✅ Scan time: 4-12 min → 2-6 min
- ✅ Coverage: Still catch real exploits
- ✅ Cost: 70-80% reduction in headless browser overhead

**Implementation Timeline:**
- Week 1: Collect execution probability data from v1.0 scans
- Week 2: Feature engineering (payload patterns, position encoding)
- Week 3: Train LightGBM model
- Week 4: Evaluate on holdout set
- Week 5: Integration + testing

---

## 4. WAF EVASION STRATEGY RECOMMENDER 🟡 ADAPTIVE LEARNING

### Current Approach
```typescript
// Hardcoded mapping: WAF → mutation strategy
if (detectedWaf === 'ModSecurity') {
    strategies = [caseFlip, doubleEncode, charSubstitution];
} else if (detectedWaf === 'F5ASM') {
    strategies = [htmlEncode, commentInject, nullByte];
} else if (detectedWaf === 'CloudFlare') {
    strategies = [caseFlip, unicodeEscape, jsCommentInject];
}
```

**Problems:**
- ❌ Only 8 WAFs hardcoded (thousands exist)
- ❌ Custom WAF rules not recognized
- ❌ No learning from what actually works
- ❌ New WAF versions break assumptions
- ❌ Zero adaptation to target-specific bypasses

### Proposed Solution: Adaptive WAF Evasion Recommender

**Model: Multi-Armed Bandit + Learned Preferences**

```
State: [waf_fingerprint, payload, mutation_strategy]
  ↓
Contextual Bandit (Thompson Sampling or LinUCB)
  ↓
For each strategy: success_rate estimate
  ↓
Output: Best strategy given WAF + context
```

**Training Data:**
- Source: Historical scan results against WAF-protected targets
- Features: WAF fingerprint, payload attempted, strategy used, result (passed/blocked)
- Labels: `mutation_passed=True/False` per strategy
- Target: 500+ interaction examples per WAF type

**Algorithm:**
```python
# Online learning during scans
for payload, strategy in payloads:
    result = test_payload(payload, strategy)  # Pass or blocked
    
    # Update bandit model
    bandit.update(
        context={'waf': detected_waf, 'payload': payload},
        action=strategy,
        reward=1.0 if result.passed else 0.0
    )
    
    # Future shots use learned success rates
    next_strategy = bandit.select(context)
```

**Expected Improvements:**
- ✅ Bypass rate: 40% → 60-70% (more successful evasions)
- ✅ Adaptability: Custom WAFs learn automatically
- ✅ Self-improving: Better strategies over time
- ✅ Coverage: Works for unknown WAFs via bandit exploration

**Integration Point:**
```python
# Replace hardcoded WAF rules
# OLD: if waf == 'ModSecurity': strategies = [...]
# NEW:
strategies = waf_evasion_recommender.rank_strategies(
    waf=detected_waf,
    payload=payload,
    beta=0.1  # exploration rate
)
```

**Implementation Timeline:**
- Week 1-2: Collect WAF interaction data from production scans
- Week 3: Implement contextual bandit (Thompson Sampling)
- Week 4: Feature engineering (WAF fingerprints, payload encoding)
- Week 5: Deploy as online learning system
- Week 6+: Continuous improvement as scan data accumulates

---

## 5. PAYLOAD RANKING/SELECTION RANKER 🟡 EFFICIENCY

### Current Approach
```python
# All 59K payloads ranked by context label
context_to_payloads = {
    'script_injection': [payload1, payload2, ...],
    'event_handler': [payload3, payload4, ...],
    ...
}

# Test first 20 per param regardless of effectiveness
payloads = context_to_payloads[detected_context][:20]
```

**Inefficiencies:**
- ❌ Same payloads tested for every target (no personalization)
- ❌ No learning from historical success rates
- ❌ Test 100 payloads when 5-10 would work
- ❌ Inefficient for time-limited scans
- ❌ No target-specific tuning

### Proposed Solution: Effectiveness Ranker v2

**Model: Learning-to-Rank (LambdaMART or Neural Ranker)**

```
Input: [payload, context, target_features, environment]
  ↓
XGBoost/LightGBM ranker (learn pairwise preferences)
  ↓
Output: ranked list of best payloads for this target
```

**Training Data:**
- Source: Historical scan results grouped by target
- Features: payload properties, context, WAF, target tech stack, execution result
- Labels: Which payloads actually worked (binary relevance)
- Target: 5000+ scan results with executed payloads

**Examples:**
```
Query: WordPress + WAF=ModSec + context=attribute
Best: [payload_X (0.95), payload_Y (0.87), payload_Z (0.73)]

Query: Node.js + No WAF + context=js_string
Best: [payload_A (0.92), payload_B (0.88), payload_C (0.81)]

Query: Java + WAF=F5 + context=html_body
Best: [payload_P (0.89), payload_Q (0.85), payload_R (0.76)]
```

**Expected Improvements:**
- ✅ Efficiency: Payloads tested: 100 → 20
- ✅ Speed: Scan time -30% with same coverage
- ✅ Accuracy: Higher-probability payloads tested first
- ✅ Adaptability: Learns best payloads per tech stack

**Integration Point:**
```python
# Instead of:
payloads = context_to_payloads[context][:20]

# Use:
payloads = payload_ranker.rank(
    context=detected_context,
    target_features=extract_features(url, headers),
    k=15  # Top 15 payloads only
)
```

**Implementation Timeline:**
- Week 1: Feature extraction from scan metadata
- Week 2: Collect 5000+ labeled examples
- Week 3: Train LambdaMART model
- Week 4: Evaluate ranking quality
- Week 5: Integration + A/B test

---

## Implementation Priority Matrix

```
        Impact
        ↑
    H   │ mXSS      False Pos
        │ Classifier Filter
        │
    M   │                    Payload Ranker
        │           Exec Prob
        │
    L   │                    WAF Recommender
        └──────────────────────────────────→
          Low    Medium    High
          Effort
```

### Phased Rollout

**Phase 1 (Months 1-2): Foundation**
- ✅ Mutation XSS Classifier (quick win)
- ✅ False Positive Filter (highest impact)
- 📊 Collect execution probability data

**Phase 2 (Months 2-3): Performance**
- ✅ Execution Probability Predictor (speed wins)
- ✅ Payload Ranking v2 (efficiency)
- 📊 Collect WAF interaction data

**Phase 3 (Months 3+): Optimization**
- ✅ WAF Evasion Recommender (adaptive learning)
- 📊 Continuous improvement from production

---

## Data Collection Strategy

All improvements rely on collecting training data from v1.0 production scans. **No external APIs needed.**

### Automated Data Pipeline

```python
# During scan execution
class ProductionDataCollector:
    def on_payload_tested(payload, result, context):
        # Store for mutation XSS classifier training
        if context == 'mutation':
            training_data.append({
                'payload': payload,
                'response_body': result.response,
                'is_mutation_xss': result.executed,
            })
        
        # Store for false positive filter
        training_data.append({
            'payload': payload,
            'position': result.reflection_position,
            'executed': result.executed,
            'confidence': result.browser_detection_confidence,
        })
        
        # Store for execution predictor
        if result.reflected:
            training_data.append({
                'payload': payload,
                'position': result.position,
                'executed': result.executed,
                'context': context,
            })
        
        # Store for payload ranker
        training_data.append({
            'payload': payload,
            'context': context,
            'target_features': extract_target_features(),
            'executed': result.executed,
        })
```

### Data Privacy Considerations
- ✅ All data stays internal (no upload to external services)
- ✅ URL patterns anonymized for ranking models
- ✅ Sensitive payloads can be filtered per client
- ✅ No customer data exposed (only vulnerability metadata)

---

## Success Metrics

| Model | Metric | Target | Baseline |
|-------|--------|--------|----------|
| mXSS Classifier | F1 Score | > 0.88 | 0.72 (heuristic) |
| False Pos Filter | Precision | > 0.85 | 0.60 (current) |
| Exec Predictor | Top-k Recall | > 0.95 | 1.0 (verify all) |
| Payload Ranker | DCG@10 | > 0.90 | N/A (baseline) |
| WAF Recommender | Bypass Rate | > 0.65 | 0.40 (hardcoded) |

---

## Resource Requirements

### Team
- 1 ML Engineer: Model development, training
- 1 Backend Engineer: Integration, data pipeline
- 0.5 Data Analyst: Data quality, labeling

### Infrastructure
- GPU: Optional (DistilBERT fine-tuning ~2 hours on CPU)
- Storage: 10-50GB for training data (internal only)
- Compute: Existing infrastructure (no new deployments needed)

### Data
- ~5000-10K labeled examples per model
- Collected during normal v1.0 operation (no manual collection burden)

---

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Model drift (new attack vectors) | Continuous retraining pipeline + manual reviews |
| False negatives (missed exploits) | Fallback to heuristics, conservative thresholds |
| Privacy/data leaks | Internal-only data, no external APIs, encryption at rest |
| Complexity | Start with simple models (logistic regression), iterate |
| Team expertise | Leverage existing DistilBERT setup, use proven algorithms |

---

## Conclusion

RedSentinel v1.0 is production-ready. These 5 ML improvements can:

- 🚀 **Double detection quality** (mXSS + false positive filter)
- ⚡ **Reduce scan time by 50%** (execution predictor + payload ranker)
- 🎯 **Enable adaptive learning** (WAF recommender)
- 💰 **Zero external data costs** (use internal training data)
- 📈 **Build competitive moat** (proprietary models)

**Recommended next step:** Start with **Mutation XSS Classifier + False Positive Filter** (6-8 week timeline) while collecting data for later phases.

---

**Document Version:** 1.0  
**Last Updated:** March 6, 2026  
**Status:** Planning Phase
