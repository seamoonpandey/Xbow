#!/usr/bin/env python3
"""
eval/analysis/portswigger_analyzer.py — PortSwigger payload coverage analysis.

Analyzes PortSwigger payload detection rates per context type from an archived run.

Usage:
    python3 eval/analysis/portswigger_analyzer.py            # latest run
    python3 eval/analysis/portswigger_analyzer.py <run_id>   # specific run
    python3 eval/analysis/portswigger_analyzer.py --json     # JSON output
"""

import json
import sys
from pathlib import Path

# Use shared utilities from eval/_common.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "eval"))
from _common import resolve_run, load_summary, load_portswigger, ARCHIVE_DIR


def analyze(ps_data):
    """Analyze PortSwigger coverage results."""
    analysis = {
        "total_payloads": ps_data.get("total_portswigger_payloads", 0),
        "sample_tested": ps_data.get("sample_tested", 0),
        "detected": ps_data.get("detected", 0),
        "browser_executed": ps_data.get("browser_executed", 0),
        "overall_coverage_pct": ps_data.get("coverage_pct", 0),
        "overall_execution_pct": ps_data.get("execution_pct", 0),
        "context_breakdown": ps_data.get("context_breakdown", {}),
        "findings": [],
    }

    # Per-context analysis
    for ctx, stats in sorted(ps_data.get("context_breakdown", {}).items(),
                             key=lambda x: -x[1]["total"]):
        ctx_analysis = {
            "context": ctx,
            "total": stats.get("total", 0),
            "detected": stats.get("detected", 0),
            "executed": stats.get("executed", 0),
            "coverage_pct": stats.get("coverage_pct", 0),
            "execution_pct": round(stats.get("executed", 0) / max(stats.get("total", 0), 1) * 100, 1),
        }

        if ctx_analysis["coverage_pct"] < 50:
            analysis["findings"].append({
                "severity": "high",
                "context": ctx,
                "message": f"Low detection rate: {ctx_analysis['coverage_pct']}% ({ctx_analysis['detected']}/{ctx_analysis['total']})",
            })
        elif ctx_analysis["coverage_pct"] < 80:
            analysis["findings"].append({
                "severity": "medium",
                "context": ctx,
                "message": f"Moderate detection rate: {ctx_analysis['coverage_pct']}% ({ctx_analysis['detected']}/{ctx_analysis['total']})",
            })

        if ctx_analysis["execution_pct"] < 30:
            analysis["findings"].append({
                "severity": "low",
                "context": ctx,
                "message": f"Low browser-execution rate ({ctx_analysis['execution_pct']}%) — payloads may need click/event to fire",
            })

    # Overall assessment
    if analysis["overall_coverage_pct"] >= 95:
        analysis["assessment"] = "excellent"
    elif analysis["overall_coverage_pct"] >= 80:
        analysis["assessment"] = "good"
    elif analysis["overall_coverage_pct"] >= 60:
        analysis["assessment"] = "moderate"
    else:
        analysis["assessment"] = "needs_improvement"

    return analysis


def print_analysis(analysis):
    """Print formatted PortSwigger analysis."""
    print(f"\n{'='*60}")
    print(f"  PORSWIGGER COVERAGE ANALYSIS")
    print(f"{'='*60}")
    print(f"\n  Overall:")
    print(f"    Total payloads in dataset: {analysis['total_payloads']}")
    print(f"    Sample tested:             {analysis['sample_tested']}")
    print(f"    Detected:                  {analysis['detected']} ({analysis['overall_coverage_pct']}%)")
    print(f"    Browser-executed:          {analysis['browser_executed']} ({analysis['overall_execution_pct']}%)")
    print(f"    Assessment:                {analysis['assessment']}")

    print(f"\n  {'Context':25s} {'Total':6s} {'Det':5s} {'Exec':5s} {'Coverage':9s}")
    print(f"  {'─'*25} {'─'*6} {'─'*5} {'─'*5} {'─'*9}")
    for ctx, stats in sorted(analysis.get("context_breakdown", {}).items(),
                             key=lambda x: -x[1]["total"]):
        print(f"  {ctx:25s} {stats['total']:6d} {stats['detected']:5d} "
              f"{stats['executed']:5d} {stats['coverage_pct']:8.1f}%")

    findings = analysis.get("findings", [])
    if findings:
        print(f"\n  🔍 Findings:")
        for f in findings:
            icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(f.get("severity"), "⚪")
            print(f"    {icon} [{f.get('severity').upper()}] {f.get('context')}: {f.get('message')}")

    print()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PortSwigger coverage analysis")
    parser.add_argument("run_id", nargs="?", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    run_dir = resolve_run(args.run_id)

    ps_data = load_portswigger(run_dir)
    if not ps_data:
        sys.exit(1)

    analysis = analyze(ps_data)

    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print_analysis(analysis)

    # Auto-save
    analysis_file = run_dir / "analysis" / "portswigger_analysis.json"
    analysis_file.parent.mkdir(parents=True, exist_ok=True)
    analysis_file.write_text(json.dumps(analysis, indent=2))
    print(f"  ✅ PortSwigger analysis saved to: {analysis_file}")


if __name__ == "__main__":
    main()
