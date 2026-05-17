#!/usr/bin/env python3
"""
eval/analysis/metrics.py — Compute evaluation metrics from an archived run.

Usage:
    python3 eval/analysis/metrics.py                    # latest run
    python3 eval/analysis/metrics.py <run_id>           # specific run
    python3 eval/analysis/metrics.py --all              # all runs
"""

import json
import sys
from pathlib import Path

# Use shared utilities from eval/_common.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "eval"))
from _common import resolve_run, load_summary, ARCHIVE_DIR


def print_metrics(summary, run_name):
    """Print formatted metrics from a summary dict."""
    m = summary.get("metrics", {})
    s = summary.get("_meta", {})

    print(f"\n{'='*60}")
    print(f"  Run: {run_name}")
    print(f"  Timestamp: {s.get('timestamp', '?')[:19]}")
    print(f"  Target: {s.get('target', '?')}")
    print(f"{'='*60}")

    print(f"\n  📊 Executive Summary")
    print(f"  {'─'*50}")
    print(f"    Precision:          {m.get('precision', '?'):>8}")
    print(f"    Recall:             {m.get('recall', '?'):>8}")
    print(f"    F1-Score:           {m.get('f1', '?'):>8}")
    print(f"  {'─'*50}")
    print(f"    True Positives:     {m.get('tp', '?'):>8}")
    print(f"    False Negatives:    {m.get('fn', '?'):>8}")
    print(f"    True Negatives:     {m.get('tn', '?'):>8}")
    print(f"    False Positives:    {m.get('fp', '?'):>8}")
    print(f"  {'─'*50}")
    print(f"    Endpoints:          {m.get('total_endpoints', '?'):>8}")
    print(f"    Vulns Found:        {m.get('total_vulns', '?'):>8}")
    print(f"    Browser-Confirmed:  {m.get('total_executed', '?'):>8}")
    print(f"    Errors:             {m.get('endpoints_with_errors', '?'):>8}")

    # Category breakdown
    categories = m.get("categories", {})
    if categories:
        print(f"\n  📁 Category Breakdown")
        print(f"  {'─'*50}")
        print(f"    {'Category':20s} {'Endpoints':10s} {'Vulns':8s} {'Exec':6s} {'Errors':6s}")
        print(f"    {'─'*20} {'─'*10} {'─'*8} {'─'*6} {'─'*6}")
        for cat, stats in sorted(categories.items()):
            print(f"    {cat:20s} {stats['endpoints']:10d} {stats['vulns']:8d} "
                  f"{stats['executed']:6d} {stats['errors']:6d}")

    # PortSwigger
    ps = summary.get("portswigger")
    if ps:
        print(f"\n  🧪 PortSwigger Coverage: {ps.get('coverage_pct', '?')}% "
              f"({ps.get('detected', 0)}/{ps.get('sample_tested', 0)})")
        print(f"     Browser-Confirmed: {ps.get('execution_pct', '?')}%")

    # False negatives
    endpoints = summary.get("endpoints", {})
    fns = [(name, r) for name, r in sorted(endpoints.items())
           if r.get("expected") == "Vuln" and r.get("vulns", 0) == 0 and not r.get("error")]
    if fns:
        print(f"\n  ❌ False Negatives ({len(fns)})")
        for name, r in fns:
            print(f"    - {name}: {r.get('category', '?')}")
    else:
        print(f"\n  ✅ No false negatives!")

    print()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Compute metrics from evaluation run")
    parser.add_argument("run_id", nargs="?", default=None,
                        help="Run ID (directory name in eval/archive/)")
    parser.add_argument("--all", action="store_true",
                        help="Show metrics for all runs")
    args = parser.parse_args()

    if args.all:
        runs = sorted(ARCHIVE_DIR.iterdir()) if ARCHIVE_DIR.exists() else []
        for run_dir in runs:
            if (run_dir / "summary.json").exists():
                s = load_summary(run_dir)
                if s:
                    print_metrics(s, run_dir.name)
    else:
        run_dir = resolve_run(args.run_id)
        s = load_summary(run_dir)
        if s:
            print_metrics(s, run_dir.name)


if __name__ == "__main__":
    main()
