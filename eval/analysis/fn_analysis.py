#!/usr/bin/env python3
"""
eval/analysis/fn_analysis.py — False negative analysis from an archived run.

Analyzes endpoints that were expected to be vulnerable but returned 0 vulns.
Provides payload-level breakdown and root cause suggestions.

Usage:
    python3 eval/analysis/fn_analysis.py               # latest run
    python3 eval/analysis/fn_analysis.py <run_id>      # specific run
    python3 eval/analysis/fn_analysis.py --json        # JSON output
"""

import json
import sys
from pathlib import Path

# Use shared utilities from eval/_common.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "eval"))
from _common import resolve_run, load_summary, ARCHIVE_DIR


def analyze_false_negatives(summary):
    """Analyze false negatives and return structured analysis."""
    endpoints = summary.get("endpoints", {})
    fns = {name: r for name, r in sorted(endpoints.items())
           if r.get("expected") == "Vuln" and r.get("vulns", 0) == 0 and not r.get("error")}

    analysis = {
        "run_timestamp": summary.get("_meta", {}).get("timestamp", "?"),
        "total_fns": len(fns),
        "fn_endpoints": [],
        "per_category": {},
        "recommendations": [],
    }

    for name, r in fns.items():
        cat = r.get("category", "Other")
        analysis["per_category"].setdefault(cat, 0)
        analysis["per_category"][cat] += 1

        entry = {
            "name": name,
            "category": cat,
            "url": r.get("url", "?"),
            "expected": r.get("expected", "?"),
            "payloads_sent": r.get("total_payloads", 0),
            "results_returned": r.get("total_results", 0),
            "reflected": r.get("reflected", 0),
            "executed": r.get("executed", 0),
        }

        # Try to suggest root cause based on endpoint name/type
        name_lower = name.lower()
        if "waf" in name_lower:
            entry["suggested_cause"] = "WAF blocklist likely suppressing payloads"
            entry["suggested_fix"] = "Use string-split payloads (e.g., 'ale'+'rt(1)') or event handlers"
        elif "comment" in name_lower and "bypass" in name_lower:
            entry["suggested_cause"] = "Comment-strip filter removes payload wrapper; reflection mismatch"
            entry["suggested_fix"] = "Send payload without comment wrapper, or use direct tag injection"
        elif "profile" in name_lower and "stored" in name_lower:
            entry["suggested_cause"] = "Potential race condition in shared profile_db"
            entry["suggested_fix"] = "Split into per-param endpoints to avoid concurrent POST overwrites"
        elif "meta" in name_lower or "header" in name_lower:
            entry["suggested_cause"] = "Known safe: header/metadata injection doesn't execute in browser"
            entry["suggested_fix"] = "Mark as Safe in manifest (expected=Safe)"
        elif "dom" in name_lower:
            entry["suggested_cause"] = "DOM sink may require fragment (#) based payloads"
            entry["suggested_fix"] = "Test with fragment-specific payloads or check browser verifier"
        elif "stored" in name_lower:
            entry["suggested_cause"] = "Stored mode may have display URL / form field mismatch"
            entry["suggested_fix"] = "Verify display_url reflects stored content, check form_fields"
        elif "mutation" in name_lower or "mutation" in cat.lower():
            entry["suggested_cause"] = "Mutation XSS requires specific HTML parser quirks"
            entry["suggested_fix"] = "Test with known mXSS payloads (e.g., <noscript>, <style> mutations)"
        else:
            entry["suggested_cause"] = "Unknown — check raw results for reflection/execution details"
            entry["suggested_fix"] = "Review raw_fuzzer_response in results/ directory"

        analysis["fn_endpoints"].append(entry)

    # Generate recommendations
    if fns:
        analysis["recommendations"].append({
            "severity": "high",
            "message": f"{len(fns)} endpoint(s) expected vulnerable but returned 0 vulns",
        })
        for entry in analysis["fn_endpoints"]:
            analysis["recommendations"].append({
                "severity": "medium",
                "endpoint": entry["name"],
                "message": entry["suggested_cause"],
                "fix": entry["suggested_fix"],
            })

    return analysis


def main():
    import argparse
    parser = argparse.ArgumentParser(description="False negative analysis from evaluation run")
    parser.add_argument("run_id", nargs="?", default=None,
                        help="Run ID (directory name in eval/archive/)")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON instead of formatted text")
    parser.add_argument("--save", action="store_true",
                        help="Save analysis to run directory")
    args = parser.parse_args()

    run_dir = resolve_run(args.run_id)
    summary = load_summary(run_dir)
    if not summary:
        sys.exit(1)

    analysis = analyze_false_negatives(summary)

    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  FALSE NEGATIVE ANALYSIS")
        print(f"  Run: {run_dir.name}")
        print(f"{'='*60}")

        if analysis["total_fns"] == 0:
            print(f"\n  ✅ No false negatives! All vulnerable endpoints detected correctly.")
        else:
            print(f"\n  ❌ {analysis['total_fns']} False Negative(s) Found\n")
            print(f"  {'Endpoint':30s} {'Category':12s} {'Payloads':10s} {'Refl':5s} {'Exec':5s}")
            print(f"  {'─'*30} {'─'*12} {'─'*10} {'─'*5} {'─'*5}")
            for entry in analysis["fn_endpoints"]:
                print(f"  {entry['name']:30s} {entry['category']:12s} "
                      f"{entry['payloads_sent']:5d}/{entry['results_returned']:3d} "
                      f"{entry['reflected']:5d} {entry['executed']:5d}")

            print(f"\n  🔍 Root Cause Suggestions\n")
            for entry in analysis["fn_endpoints"]:
                print(f"  {entry['name']}:")
                print(f"    Cause: {entry['suggested_cause']}")
                print(f"    Fix:   {entry['suggested_fix']}")
                print()

        # Per-category breakdown
        if analysis["per_category"]:
            print(f"  📁 Per-Category FN Breakdown:")
            for cat, count in sorted(analysis["per_category"].items()):
                print(f"    {cat}: {count}")
            print()

    # Save analysis to run directory
    if args.save:
        analysis_file = run_dir / "analysis" / "false_negatives.json"
        analysis_file.parent.mkdir(parents=True, exist_ok=True)
        analysis_file.write_text(json.dumps(analysis, indent=2))
        print(f"  ✅ Analysis saved to: {analysis_file}")


if __name__ == "__main__":
    main()
