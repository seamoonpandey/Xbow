# Red Sentinel Evaluation Reports

This directory contains all evaluation results, cross-tool comparisons, and analysis scripts.

## Quick Navigation

| If you want to... | Read this |
|---|---|
| See the **47-endpoint Red Sentinel-only evaluation** (TP=44, FN=0, FP=0, TN=3, F1=1.000) | [`evaluation_report.md`](evaluation_report.md) (Step 10) |
| Compare Red Sentinel vs ZAP/XSStrike/Dalfox on **4 base tests** (T1-T4) | [`evaluation_report.md`](evaluation_report.md) (Steps 2-8) |
| Compare Red Sentinel vs ZAP/XSStrike/Dalfox on **14 endpoints** with timing | [`CROSS_PLATFORM_COMPARISON.md`](CROSS_PLATFORM_COMPARISON.md) |
| Compare Red Sentinel vs ZAP/XSStrike/Dalfox on **6 endpoints** | [`CROSS_TOOL_COMPARISON.md`](CROSS_TOOL_COMPARISON.md) |
| See **real-world target results** (Juice Shop, WebGoat, Benchmark) | [`MULTI_TARGET_EVALUATION.md`](MULTI_TARGET_EVALUATION.md) |
| See raw per-endpoint comparison data | `comparison_results/v3_clean/` |
| View archived run results | `archive/` (run `python3 eval/analysis/metrics.py <run-name>`) |
| Compute metrics from an archived run | `analysis/metrics.py` |
| Run a fresh evaluation | `run.py` (see Reproducibility section below) |

## Report Scope Summary

| Report | Endpoints | Red Sentinel Only? | PortSwigger | Includes Timing? | Browser Verified? |
|--------|:---------:|:------------------:|:-----------:|:----------------:|:-----------------:|
| `evaluation_report.md` (47-endpoint) | 47 | ✅ Yes | 96.0% | ❌ | ✅ 74/96 |
| `evaluation_report.md` (T1-T4) | 4 | ❌ (4 tools) | — | ✅ | ✅ 9/9 |
| `CROSS_PLATFORM_COMPARISON.md` | 14 | ❌ (4 tools) | — | ✅ | ✅ 9/11 |
| `CROSS_TOOL_COMPARISON.md` | 6 | ❌ (4 tools) | 96.0% | ✅ | ✅ 11/13 |
| `MULTI_TARGET_EVALUATION.md` | 17+4 | ✅ (RS + 3 tools on T1-T4) | — | ✅ | ✅ (exploitable only) |

## Why Different Numbers?

Different reports show different metrics because they test **different endpoint sets** with **different counting methodologies**:

1. **47-endpoint eval** (Red Sentinel only, `eval/run.py` pipeline): Uses **browser-execution strict counting**. A "vulnerability" is only counted if the payload actually executes in a headless browser. Safe endpoints that reflect input but don't execute get 0 vulns → **FP=0**.

2. **Cross-tool comparisons** (`run_comparison.py`): Uses **reflection-based detection** matching how other tools work. If a tool reports any alert/reflection, it's detected. This matches the other tools' methodology but produces higher FP counts for tools that lack browser verification.

3. **Real-world targets** (`MULTI_TARGET_EVALUATION.md`): Tests against actual applications (Juice Shop, WebGoat, Benchmark), which expose architectural limitations (SPA JSON, auth flows, POST/Referer injection) rather than detection bugs.

## Reproducibility

### Prerequisites
```bash
# Start services
cd /home/moon/Projects/xbow
docker compose up -d exploitable context payload-gen fuzzer

# Verify
curl -s http://localhost:9090/health    # exploitable app (200)
curl -s http://localhost:5003/health    # fuzzer (200)
```

### Run a fresh evaluation
```bash
# 47-endpoint full eval
python3 eval/run.py --output fresh-full-eval

# Cross-tool comparison (14 endpoints)
python3 eval/run_comparison.py --output fresh-compare

# View results
python3 eval/analysis/metrics.py fresh-full-eval
python3 eval/analysis/metrics.py fresh-compare
```

### View archived runs
```bash
# List all archived runs
ls eval/archive/

# Show metrics for a specific run
python3 eval/analysis/metrics.py full-exploitable-eval
python3 eval/analysis/metrics.py multi-type-comparison

# Show all runs
python3 eval/analysis/metrics.py --all
```

## Archived Snapshot

The authoritative run data is in `eval/archive/`. Key runs:

| Run | Endpoints | Target | TP | FN | FP | TN | F1 | PortSwigger |
|-----|:---------:|:------:|:--:|:--:|:--:|:--:|:--:|:-----------:|
| `full-exploitable-eval` | 47 | exploitable (9090) | 44 | 0 | 0 | 3 | **1.000** | 96.0% |
| `multi-type-comparison` | 14 | exploitable (9090) | 11 | 0 | 0 | 1 | **1.000** | 96.0% |
| `exploitable-compare` | 6 | exploitable (9090) | 5 | 0 | 0 | 1 | **1.000** | 96.0% |
| `juice-shop-eval` | 53 | juice-shop (3000) | 44 | 3 | 0 | 3 | 0.967 | — |
| `webgoat-eval-v2` | 52 | webgoat (8080) | 44 | 4 | 0 | 4 | 0.957 | — |
| `benchmark-eval-v3` | 53 | benchmark (8443) | 44 | 3 | 0 | 6 | 0.967 | — |

> **Note:** Juice Shop, WebGoat, and Benchmark runs include the 47 exploitable endpoints plus target-specific endpoints. FN counts in those runs come from real-world target limitations (SPA JSON, auth, POST/Referer), not from detection failures on the exploitable app.
