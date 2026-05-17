#!/usr/bin/env python3
"""
eval/analysis/cross_target.py — Cross-Target Comparison Analysis

Aggregates evaluation results from multiple target runs (exploitable, Juice Shop,
WebGoat, OWASP Benchmark) and produces a unified comparison table.

Usage:
    python3 eval/analysis/cross_target.py                           # Compare latest runs across targets
    python3 eval/analysis/cross_target.py --targets jshop,webgoat   # Specific targets
    python3 eval/analysis/cross_target.py --json                    # JSON output
    python3 eval/analysis/cross_target.py --save                    # Save to archive
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add parent to path for _common
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _common import load_summary, ARCHIVE_DIR


TARGETS_REGISTRY = ARCHIVE_DIR.parent / "targets" / "_targets.json"


def get_target_runs():
    """Discover evaluation runs grouped by target name from archive.

    Returns dict mapping target_name -> list of (run_dir, summary) tuples,
    sorted newest first.
    """
    if not ARCHIVE_DIR.exists():
        return {}

    # Load target registry to get known target names
    known_targets = {"exploitable"}
    if TARGETS_REGISTRY.exists():
        with open(TARGETS_REGISTRY) as f:
            reg = json.load(f)
        for t in reg.get("targets", []):
            known_targets.add(t["name"])

    # Group runs by target name
    target_runs = {t: [] for t in known_targets}
    target_runs["unknown"] = []

    for run_dir in sorted(ARCHIVE_DIR.iterdir(), reverse=True):
        meta_file = run_dir / "_meta.json"
        summary_file = run_dir / "summary.json"
        if not meta_file.exists() or not summary_file.exists():
            continue

        with open(meta_file) as f:
            meta = json.load(f)
        with open(summary_file) as f:
            summary = json.load(f)

        target_name = meta.get("target_name", "unknown")
        if target_name not in target_runs:
            target_runs[target_name] = []

        target_runs[target_name].append((run_dir, meta, summary))

    # Remove empty target groups
    return {k: v for k, v in target_runs.items() if v}


def build_comparison(target_runs):
    """Build a cross-target comparison table.

    Returns dict with per-target metrics.
    """
    comparison = {}

    for target_name, runs in target_runs.items():
        # Take the most recent run for this target
        run_dir, meta, summary = runs[0]
        metrics = summary.get("metrics", {})

        # Count categories
        categories = metrics.get("categories", {})

        comparison[target_name] = {
            "run_id": run_dir.name,
            "timestamp": meta.get("timestamp", ""),
            "target_url": meta.get("target_url", ""),
            "total_endpoints": metrics.get("total_endpoints", 0),
            "total_vulns": metrics.get("total_vulns", 0),
            "total_executed": metrics.get("total_executed", 0),
            "total_reflected": metrics.get("total_reflected", 0),
            "tp": metrics.get("tp", 0),
            "fn": metrics.get("fn", 0),
            "tn": metrics.get("tn", 0),
            "fp": metrics.get("fp", 0),
            "precision": metrics.get("precision", 0),
            "recall": metrics.get("recall", 0),
            "f1": metrics.get("f1", 0),
            "errors": metrics.get("endpoints_with_errors", 0),
            "categories": {k: v.get("endpoints", 0) for k, v in categories.items()},
            "portswigger_coverage": summary.get("portswigger", {}).get("coverage_pct", None),
            "run_count": len(runs),
        }

    return comparison


def print_comparison_table(comparison):
    """Print a formatted cross-target comparison table."""
    if not comparison:
        print("[!] No runs found to compare.")
        return

    print("\n" + "=" * 80)
    print("  CROSS-TARGET EVALUATION COMPARISON")
    print("=" * 80)

    headers = ["Target", "Endpoints", "Vulns", "TP", "FN", "TN", "FP",
               "Prec", "Recall", "F1", "Exec%", "Run ID"]
    col_widths = [18, 10, 8, 6, 6, 6, 6, 7, 8, 7, 7, 20]

    # Header row
    header = "  " + " │ ".join(h.ljust(w) for h, w in zip(headers, col_widths))
    print(header)
    print("  " + "─" * (sum(col_widths) + len(col_widths) * 3 - 1))

    # Data rows
    for target_name in sorted(comparison.keys(), key=lambda t: -comparison[t].get("f1", 0)):
        c = comparison[target_name]
        exec_pct = round(c["total_executed"] / c["total_vulns"] * 100, 1) if c["total_vulns"] else 0
        run_short = c["run_id"][:18] if len(c["run_id"]) > 18 else c["run_id"]

        row = [
            target_name[:16].ljust(18),
            str(c["total_endpoints"]).rjust(10),
            str(c["total_vulns"]).rjust(8),
            str(c["tp"]).rjust(6),
            str(c["fn"]).rjust(6),
            str(c["tn"]).rjust(6),
            str(c["fp"]).rjust(6),
            f"{c['precision']:.3f}".rjust(7),
            f"{c['recall']:.3f}".rjust(8),
            f"{c['f1']:.3f}".rjust(7),
            f"{exec_pct}%".rjust(7),
            run_short.rjust(20),
        ]
        print("  " + " │ ".join(row))

    print()

    # Category breakdown
    print("── Category Breakdown ──")
    all_categories = set()
    for c in comparison.values():
        all_categories.update(c.get("categories", {}).keys())

    cat_headers = ["Target"] + sorted(all_categories)
    print(f"  {'Target':18s} " + " ".join(f"{c:15s}" for c in sorted(all_categories)))
    print(f"  {'─'*18} " + " ".join(f"{'─'*15}" for _ in sorted(all_categories)))

    for target_name in sorted(comparison.keys()):
        c = comparison[target_name]
        cats = c.get("categories", {})
        cat_vals = " ".join(f"{cats.get(cat, 0):>15}" for cat in sorted(all_categories))
        print(f"  {target_name[:16]:18s} {cat_vals}")

    print()

    # Per-target portswigger coverage
    has_ps = any(c.get("portswigger_coverage") is not None for c in comparison.values())
    if has_ps:
        print("── PortSwigger Coverage ──")
        for target_name in sorted(comparison.keys()):
            c = comparison[target_name]
            ps = c.get("portswigger_coverage")
            if ps is not None:
                print(f"  {target_name[:16]:18s}  {ps:.1f}%")
        print()


def compute_rankings(comparison):
    """Compute a ranking score for each target based on F1, vulns, and errors.

    Score: f1 * 0.5 + (vulns_endpoints_ratio) * 0.3 - (errors_ratio) * 0.2
    Higher is better.
    """
    max_endpoints = max((c["total_endpoints"] for c in comparison.values()), default=1)
    max_vulns = max((c["total_vulns"] for c in comparison.values()), default=1)

    rankings = []
    for target_name, c in comparison.items():
        vuln_ratio = c["total_vulns"] / max_vulns if max_vulns else 0
        error_ratio = c["errors"] / c["total_endpoints"] if c["total_endpoints"] else 0
        score = c["f1"] * 0.5 + vuln_ratio * 0.3 - error_ratio * 0.2
        rankings.append((target_name, round(score, 3), c["f1"], c["total_vulns"], c["errors"]))

    rankings.sort(key=lambda x: -x[1])

    print("── Target Rankings ──")
    print(f"  {'Rank':5s} {'Target':18s} {'Score':7s} {'F1':7s} {'Vulns':7s} {'Errors':7s}")
    print(f"  {'─'*5} {'─'*18} {'─'*7} {'─'*7} {'─'*7} {'─'*7}")
    for i, (name, score, f1, vulns, errors) in enumerate(rankings, 1):
        print(f"  {i:<5d} {name[:16]:18s} {score:<7.3f} {f1:<7.3f} {vulns:<7d} {errors:<7d}")
    print()


def save_cross_target_report(comparison, rankings, run_dir):
    """Save the cross-target comparison as JSON in the specified run directory."""
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "targets_compared": len(comparison),
        "comparison": comparison,
        "rankings": [{"rank": i+1, "target": r[0], "score": r[1], "f1": r[2],
                       "vulns": r[3], "errors": r[4]}
                      for i, r in enumerate(rankings)],
    }
    save_path = run_dir / "cross_target_comparison.json"
    save_path.write_text(json.dumps(report, indent=2))
    print(f"  ✅ Cross-target comparison saved to: {save_path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Cross-Target Evaluation Comparison")
    parser.add_argument("--targets", type=str, default=None,
                        help="Comma-separated list of target names to compare (default: all)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--save", type=str, default=None,
                        help="Save comparison to a specific run directory")
    args = parser.parse_args()

    all_runs = get_target_runs()

    if not all_runs:
        print("[!] No evaluation runs found in eval/archive/")
        print("    Run python3 eval/run.py --target <name> first.")
        sys.exit(1)

    # Filter by target names if specified
    if args.targets:
        target_filter = set(args.targets.split(","))
        all_runs = {k: v for k, v in all_runs.items() if k in target_filter}

    comparison = build_comparison(all_runs)

    if args.json:
        print(json.dumps({"cross_target": comparison}, indent=2))
        return 0

    print_comparison_table(comparison)
    rankings = compute_rankings(comparison)

    if args.save:
        save_dir = ARCHIVE_DIR / args.save
        if save_dir.exists():
            save_cross_target_report(comparison, rankings, save_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
