#!/usr/bin/env python3
"""
eval/analysis/context_coverage.py — Context coverage analysis.

Analyzes how well the scanner covers different injection contexts
(body, attribute, script, event, href, etc.) across all endpoints.

Usage:
    python3 eval/analysis/context_coverage.py               # latest run
    python3 eval/analysis/context_coverage.py <run_id>      # specific run
    python3 eval/analysis/context_coverage.py --json        # JSON output
"""

import json
import sys
from pathlib import Path

# Use shared utilities from eval/_common.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "eval"))
from _common import resolve_run, load_summary, ARCHIVE_DIR


# Context classification rules based on endpoint name and URL patterns
CONTEXT_PATTERNS = {
    "body":          ["/reflected/body", "/reflected/multiparams", "/bypass/", "/mutation/innerhtml",
                      "/mutation/dangerouslyhtml", "T1", "T2", "T3", "T4"],
    "attribute":     ["/reflected/attribute", "/bypass/angle-only", "/bypass/tag-strip",
                      "/bypass/quote-escape"],
    "attribute_unquoted": ["/reflected/attribute-unquoted", "/reflected/css"],
    "script_var":    ["/reflected/script", "/reflected/js-string"],
    "event_handler": ["/reflected/event"],
    "href":          ["/reflected/href", "/reflected/iframe"],
    "meta_redirect": ["/reflected/meta"],
    "textarea":      ["/reflected/textarea"],
    "html_comment":  ["/reflected/comment"],
    "style_block":   ["/reflected/style"],
    "jsonp":         ["/reflected/json"],
    "dom_write":     ["/dom/write", "/dom/hash-write"],
    "dom_innerhtml": ["/dom/innerhtml", "/dom/cookie", "/dom/localstorage", "/mutation/svg"],
    "dom_eval":      ["/dom/eval", "/dom/settimeout"],
    "dom_jquery":    ["/dom/jquery"],
    "dom_redirect":  ["/dom/url-replace"],
    "dom_srcdoc":    ["/dom/srcdoc"],
    "stored_body":   ["/stored/comments", "/stored/guestbook", "/stored/notes", "/stored/profile-bio"],
    "stored_attr":   ["/stored/profile-website"],
    "angular":       ["/mutation/angular"],
}


def classify_context(endpoint_name, url):
    """Classify an endpoint into injection context(s)."""
    matched = []
    for ctx, patterns in CONTEXT_PATTERNS.items():
        for pat in patterns:
            if pat in url or pat.lower() in endpoint_name.lower():
                matched.append(ctx)
                break
    return matched or ["unknown"]


def analyze_coverage(summary):
    """Analyze context coverage from summary results."""
    endpoints = summary.get("endpoints", {})

    context_stats = {}
    unclassified = []

    for name, r in endpoints.items():
        contexts = classify_context(name, r.get("url", ""))
        is_miss = r.get("expected") == "Vuln" and r.get("vulns", 0) == 0

        if contexts == ["unknown"]:
            unclassified.append(name)

        for ctx in contexts:
            if ctx not in context_stats:
                context_stats[ctx] = {
                    "total": 0, "vulns_found": 0, "misses": 0,
                    "executed": 0, "endpoints": [],
                }
            context_stats[ctx]["total"] += 1
            context_stats[ctx]["vulns_found"] += r.get("vulns", 0)
            context_stats[ctx]["executed"] += r.get("executed", 0)
            if is_miss:
                context_stats[ctx]["misses"] += 1
            context_stats[ctx]["endpoints"].append(name)

    analysis = {
        "total_contexts": len(context_stats),
        "context_coverage": {},
        "unclassified_endpoints": unclassified,
        "summary": {
            "total_endpoints": len(endpoints),
            "vulns_found": sum(r.get("vulns", 0) for r in endpoints.values()),
            "total_contexts_covered": len(context_stats),
        },
    }

    for ctx, stats in sorted(context_stats.items()):
        detection_rate = round(
            (stats["total"] - stats["misses"]) / stats["total"] * 100
            if stats["total"] > 0 else 0, 1
        )
        vulns_per_ep = round(stats["vulns_found"] / stats["total"], 1) if stats["total"] > 0 else 0

        analysis["context_coverage"][ctx] = {
            "endpoints": stats["total"],
            "vulns_found": stats["vulns_found"],
            "executed": stats["executed"],
            "misses": stats["misses"],
            "detection_rate_pct": detection_rate,
            "avg_vulns_per_endpoint": vulns_per_ep,
            "endpoint_names": stats["endpoints"],
        }

    return analysis


def print_analysis(analysis):
    """Print formatted context coverage analysis."""
    print(f"\n{'='*60}")
    print(f"  CONTEXT COVERAGE ANALYSIS")
    print(f"{'='*60}")
    print(f"\n  Coverage Summary:")
    print(f"    Total endpoints:     {analysis['summary']['total_endpoints']}")
    print(f"    Vulns found:         {analysis['summary']['vulns_found']}")
    print(f"    Contexts covered:    {analysis['summary']['total_contexts_covered']}")

    print(f"\n  {'Context':25s} {'Eps':4s} {'Vulns':6s} {'Exec':5s} {'Miss':5s} {'Detect%':8s}")
    print(f"  {'─'*25} {'─'*4} {'─'*6} {'─'*5} {'─'*5} {'─'*8}")
    for ctx, stats in sorted(analysis["context_coverage"].items(),
                             key=lambda x: -x[1]["endpoints"]):
        print(f"  {ctx:25s} {stats['endpoints']:4d} {stats['vulns_found']:6d} "
              f"{stats['executed']:5d} {stats['misses']:5d} {stats['detection_rate_pct']:7.1f}%")

    unclassified = analysis.get("unclassified_endpoints", [])
    if unclassified:
        print(f"\n  ⚠️  Unclassified endpoints ({len(unclassified)}):")
        for name in unclassified:
            print(f"    - {name}")

    # Low-coverage warnings
    print(f"\n  {'─'*60}")
    for ctx, stats in sorted(analysis["context_coverage"].items()):
        if stats["detection_rate_pct"] < 100 and stats["endpoints"] > 0:
            print(f"  ⚠️  {ctx}: {stats['detection_rate_pct']}% detection rate "
                  f"({stats['misses']}/{stats['endpoints']} endpoints missed)")
    print()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Context coverage analysis")
    parser.add_argument("run_id", nargs="?", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    run_dir = resolve_run(args.run_id)
    summary = load_summary(run_dir)
    if not summary:
        sys.exit(1)

    analysis = analyze_coverage(summary)

    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print_analysis(analysis)

    # Auto-save to run directory
    analysis_file = run_dir / "analysis" / "context_coverage.json"
    analysis_file.parent.mkdir(parents=True, exist_ok=True)
    analysis_file.write_text(json.dumps(analysis, indent=2))
    print(f"  ✅ Context coverage saved to: {analysis_file}")


if __name__ == "__main__":
    main()
