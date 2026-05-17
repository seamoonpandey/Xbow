# Evaluation and Results

## 6.1 Evaluation Objectives

Briefly evaluate context classification, payload ranking, vulnerability detection, and end-to-end performance.

## 6.2 Experimental Setup

See project `RUN.md` for exact environment and targets used in benchmarks.

## 6.3 Dataset Evaluation

**6.3 Dataset Evaluation**

**Table 6.1: Context Classification Dataset Distribution**

- Note: counts shown as `count (percentage of context total)` per split.

| Context | Train | Val | Test | Total |
|---|---:|---:|---:|---:|
| attribute_escape | 11742 (70.0%) | 2516 (15.0%) | 2516 (15.0%) | 16774 |
| dom_sink | 4455 (70.0%) | 955 (15.0%) | 955 (15.0%) | 6365 |
| event_handler | 4219 (70.0%) | 904 (15.0%) | 904 (15.0%) | 6027 |
| generic | 501 (70.0%) | 108 (15.1%) | 107 (14.9%) | 716 |
| js_uri | 1629 (70.0%) | 349 (15.0%) | 349 (15.0%) | 2327 |
| script_injection | 1774 (70.0%) | 380 (15.0%) | 381 (15.0%) | 2535 |
| tag_injection | 16210 (70.0%) | 3473 (15.0%) | 3474 (15.0%) | 23157 |
| template_injection | 855 (70.0%) | 183 (15.0%) | 183 (15.0%) | 1221 |

**Table 6.2: Payload Dataset Distribution**

> Verified by `scripts/dataset_stats.py` Section 11 (reproducible via `make dataset-report`).

- Total payloads: **59,122**; Unique payload texts: **59,122**

**By source**

| Source | Count | Percentage |
|---|---:|---:|
| synthetic | 40,624 | 68.7% |
| real | 18,498 | 31.3% |

**By technique**

| Technique | Count | Percentage |
|---|---:|---:|
| synthetic | 40624 | 68.7% |
| none | 16548 | 28.0% |
| url_encoding | 523 | 0.9% |
| case_variation | 424 | 0.7% |
| html_entity | 346 | 0.6% |
| comment_injection | 132 | 0.2% |
| encoding | 114 | 0.2% |
| encoding|case_variation | 94 | 0.2% |
| unicode_escape | 47 | 0.1% |
| comment_injection|case_variation | 29 | 0.0% |
| comment_injection|url_encoding | 24 | 0.0% |
| url_encoding|case_variation | 24 | 0.0% |
| html_entity|whitespace_obfuscation | 23 | 0.0% |
| html_entity|case_variation | 23 | 0.0% |
| encoding|url_encoding | 21 | 0.0% |
| comment_injection|url_encoding|case_variation | 21 | 0.0% |
| html_entity|whitespace_obfuscation|case_variation | 18 | 0.0% |
| html_entity|encoding | 12 | 0.0% |
| unicode_escape|html_entity|url_encoding | 9 | 0.0% |
| html_entity|comment_injection | 7 | 0.0% |
| unicode_escape|url_encoding | 7 | 0.0% |
| html_entity|url_encoding | 7 | 0.0% |
| unicode_escape|html_entity | 7 | 0.0% |
| html_entity|comment_injection|url_encoding | 6 | 0.0% |
| unicode_escape|case_variation | 5 | 0.0% |
| whitespace_obfuscation|case_variation | 5 | 0.0% |
| unicode_escape|encoding | 4 | 0.0% |
| html_entity|encoding|comment_injection|url_encoding | 4 | 0.0% |
| unicode_escape|comment_injection | 2 | 0.0% |
| unicode_escape|comment_injection|url_encoding|case_variation | 2 | 0.0% |
| encoding|comment_injection|url_encoding | 2 | 0.0% |
| html_entity|comment_injection|case_variation | 2 | 0.0% |
| unicode_escape|encoding|case_variation | 1 | 0.0% |
| encoding|url_encoding|case_variation | 1 | 0.0% |
| html_entity|encoding|comment_injection | 1 | 0.0% |
| whitespace_obfuscation | 1 | 0.0% |
| unicode_escape|html_entity|encoding|comment_injection | 1 | 0.0% |
| unicode_escape|url_encoding|case_variation | 1 | 0.0% |

**By severity**

| Severity | Count | Percentage |
|---|---:|---:|
| medium | 39,856 | 67.4% |
| low | 10,087 | 17.1% |
| high | 9,179 | 15.5% |

## 6.4 AI Context Classification Results

**Experiment 1: DistilBERT Context Classification**

**Table 6.3: DistilBERT Classification Results**

| Context Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| script_injection | 0.997 | 1.000 | 0.998 | 292 |
| event_handler | 0.999 | 0.997 | 0.998 | 2259 |
| js_uri | 1.000 | 0.994 | 0.997 | 166 |
| tag_injection | 0.991 | 0.993 | 0.992 | 451 |
| template_injection | 0.875 | 0.875 | 0.875 | 8 |
| dom_sink | 0.962 | 0.987 | 0.974 | 76 |
| attribute_escape | 0.993 | 0.996 | 0.995 | 280 |
| generic | 0.970 | 0.960 | 0.965 | 100 |

**Table 6.4: Confusion Matrix Summary (context)**

Context labels order: script_injection, event_handler, js_uri, tag_injection, template_injection, dom_sink, attribute_escape, generic

```
 292 0 0 0 0 0 0 0
 0 2253 0 4 0 1 1 0
 0 1 165 0 0 0 0 0
 0 2 0 448 0 0 0 1
 0 0 0 0 7 0 1 0
 0 0 0 0 0 75 0 1
 0 0 0 0 0 0 279 1
 1 0 0 0 1 2 0 96
```

## 6.5 Payload Ranking Results

**Experiment 2: XGBoost Ranking vs Baselines**

Table 6.5: Payload Ranking Comparison

| Method | Accuracy | Precision | Recall | F1 | AUC | Notes |
|---|---:|---:|---:|---:|---:|---|
| XGBoost-ranked | 0.623 | 0.681 | 0.617 | 0.647 | 0.690 | trained on 6000 samples |
| Rule-based baseline | 0.5 | - | - | - | - | heuristic baseline score 0.5 |
| Random selection | ~0.5 | - | - | - | - | expected random baseline |

## 6.6 Vulnerability Detection Results

**Table 6.6: Vulnerabilities Detected by RedSentinel (aggregate)**

| Metric | Value |
|---|---:|
| Targets tested (endpoints) | 87 |
| True positives (TP) | 74 |
| False positives (FP) | 0 |
| False negatives (FN) | 13 |
| Recall | 85.1% |
| Precision | 100.0% |
| F1 | 91.9% |
| Total scan time | 188.1s |

## 6.7 Comparison with Existing Tools

**Table 6.8: Comparison with Existing Tools (Aggregate)**

| Tool | Endpoints | TP | FP | FN | Precision | Recall | F1 | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| RedSentinel | 87 | 74 | 0 | 13 | 100.0% | 85.1% | 91.9% | 188.1s |
| OWASP ZAP | 87 | 46 | 0 | 41 | 100.0% | 52.9% | 69.2% | 704.4s |
| Dalfox | 87 | 62 | 0 | 25 | 100.0% | 71.3% | 83.2% | 143.0s |
| XSStrike | 87 | 55 | 0 | 32 | 100.0% | 63.2% | 77.5% | 303.6s |

## 6.8 End-to-End System Testing

**Table 6.10: End-to-End Pipeline Test Results (Aggregate across targets)**

| Test | Value |
|---|---:|
| Endpoints scanned | 87 |
| Vulnerabilities found (TP) | 74 |
| Missed vulnerabilities (FN) | 13 |
| Recall | 85.1% |
| End-to-end time | 188.1s |

## 6.9 Performance Evaluation

**Table 6.11: Scan Time by Target Size (approx.)**

| Target | Endpoints | Estimated scan time (s) |
|---|---:|---:|
| Nexora XSS Lab | 47 | 101.6 |
| OWASP Juice Shop | 18 | 38.9 |
| Google XSS Game | 6 | 13.0 |
| PortSwigger XSS Labs | 16 | 34.6 |

## 6.10 Discussion of Limitations

Brief notes: mock mode for benchmarks, limited target diversity, synthetic training data biases, WAF/target variability affecting ranker.
