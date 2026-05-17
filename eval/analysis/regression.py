#!/usr/bin/env python3
"""
eval/analysis/regression.py — Regression Testing for Evaluation Pipeline.

Compares a new evaluation run against a golden baseline (regression_manifest.json)
and reports whether metrics or per-endpoint results have regressed.

Usage:
    python3 eval/analysis/regression.py                          # latest run
    python3 eval/analysis/regression.py <run_id>                # specific run
    python3 eval/analysis/regression.py <run_id> --manifest my-baseline.json
    python3 eval/analysis/regression.py <run_id> --json          # JSON output (CI-friendly)
    python3 eval/analysis/regression.py <run_id> --generate-manifest
        # Generate regression_manifest.json from this run (new baseline)
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _common import resolve_run, load_summary

# Default location for the golden baseline
MANIFEST_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = MANIFEST_DIR / "regression_manifest.json"


# ── Load / Generate Baseline ─────────────────────────────────

def load_regression_manifest(path=None):
    """Load the golden regression manifest JSON."""
    p = Path(path) if path else DEFAULT_MANIFEST
    if not p.exists():
        print(f"[!] Regression manifest not found: {p}")
        print(f"    Generate one from a known-good run using:")
        print(f"    python3 eval/analysis/regression.py <run_id> --generate-manifest")
        sys.exit(1)
    with open(p) as f:
        return json.load(f)


def generate_manifest_from_summary(summary, run_id=None):
    """Build a regression manifest from a known-good run's summary."""
    meta = summary.get("_meta", {})
    endpoints = summary.get("endpoints", {})
    metrics = summary.get("metrics", {})
    portswigger = summary.get("portswigger")

    manifest = {
        "_meta": {
            "description": "Golden regression baseline — do not modify unless baseline has legitimately improved",
            "source_run": run_id or meta.get("run_id", "unknown"),
            "created": (meta.get("timestamp", "?")[:10]),
            "version": 1,
        },
        "thresholds": {
            "min_precision": metrics.get("precision", 1.0),
            "min_recall": metrics.get("recall", 0.95),
            "min_f1": metrics.get("f1", 0.97),
            "max_fn": metrics.get("fn", 0),
            "max_fp": metrics.get("fp", 0),
            "max_errors": metrics.get("endpoints_with_errors", 0),
        },
        "endpoints": {},
    }

    if portswigger:
        manifest["thresholds"]["min_portswigger_coverage"] = portswigger.get("coverage_pct", 90.0)

    for name, r in sorted(endpoints.items()):
        entry = {
            "expected": r.get("expected", "Vuln"),
        }
        if r.get("expected") == "Vuln":
            # Set min_vulns to the actual vuln count for this endpoint
            # (use at least 1 so a drop from 3→0 is caught)
            v = r.get("vulns", 0)
            entry["min_vulns"] = max(v, 1) if v > 0 else 1
        manifest["endpoints"][name] = entry

    return manifest


# ── Comparison Logic ─────────────────────────────────────────

class RegressionResult:
    """Stores pass/fail details for a regression check."""

    def __init__(self):
        self.passed = True
        self.metric_checks = []
        self.endpoint_checks = []
        self.summary = {"passed": 0, "failed": 0, "skipped": 0}

    def add_check(self, category, name, passed, expected, actual, message):
        """Record a single check result."""
        check = {
            "category": category,
            "name": name,
            "passed": passed,
            "expected": expected,
            "actual": actual,
            "message": message,
        }
        if category == "metric":
            self.metric_checks.append(check)
        else:
            self.endpoint_checks.append(check)

        if passed:
            self.summary["passed"] += 1
        else:
            self.summary["failed"] += 1
            self.passed = False

    def to_dict(self):
        """Serializable dict for JSON output."""
        return {
            "passed": self.passed,
            "summary": self.summary,
            "metric_checks": self.metric_checks,
            "endpoint_checks": self.endpoint_checks,
        }


def check_regression(summary, manifest):
    """Compare a run's summary against the golden manifest.

    Returns:
        RegressionResult with pass/fail details.
    """
    result = RegressionResult()
    thresholds = manifest.get("thresholds", {})
    met = summary.get("metrics", {})
    endpoints = summary.get("endpoints", {})
    portswigger = summary.get("portswigger")

    # ── Metric Thresholds ────────────────────────────────────
    checks = [
        ("min_precision", met.get("precision", 0), thresholds.get("min_precision", 1.0)),
        ("min_recall", met.get("recall", 0), thresholds.get("min_recall", 0.95)),
        ("min_f1", met.get("f1", 0), thresholds.get("min_f1", 0.97)),
    ]
    for name, actual, minimum in checks:
        passed = actual >= minimum
        msg = f"{name}: {actual:.3f} (threshold: ≥{minimum:.3f})"
        result.add_check("metric", name, passed, minimum, actual, msg)

    # Count-based thresholds
    count_checks = [
        ("max_fn", met.get("fn", 0), thresholds.get("max_fn", 0)),
        ("max_fp", met.get("fp", 0), thresholds.get("max_fp", 0)),
        ("max_errors", met.get("endpoints_with_errors", 0), thresholds.get("max_errors", 0)),
    ]
    for name, actual, max_allowed in count_checks:
        passed = actual <= max_allowed
        msg = f"{name}: {actual} (threshold: ≤{max_allowed})"
        result.add_check("metric", name, passed, max_allowed, actual, msg)

    # PortSwigger coverage
    if portswigger:
        ps_min = thresholds.get("min_portswigger_coverage", 90.0)
        ps_actual = portswigger.get("coverage_pct", 0)
        passed = ps_actual >= ps_min
        result.add_check("metric", "min_portswigger_coverage", passed, ps_min, ps_actual,
                         f"PortSwigger coverage: {ps_actual}% (threshold: ≥{ps_min}%)")

    # ── Per-Endpoint Checks ──────────────────────────────────
    manifest_eps = manifest.get("endpoints", {})
    run_eps = summary.get("endpoints", {})

    for name, expected_entry in sorted(manifest_eps.items()):
        run_entry = run_eps.get(name)
        if run_entry is None:
            result.add_check("endpoint", name, False, "endpoint exists",
                             "missing", f"Endpoint '{name}' not found in run results")
            continue

        expected_type = expected_entry.get("expected", "Vuln")

        if expected_type == "Vuln":
            min_vulns = expected_entry.get("min_vulns", 1)
            actual_vulns = run_entry.get("vulns", 0)
            is_error = run_entry.get("error") is not None

            if is_error:
                result.add_check("endpoint", name, False, min_vulns, "error",
                                 f"Endpoint returned error: {run_entry['error'][:100]}")
            elif actual_vulns < min_vulns:
                result.add_check("endpoint", name, False, min_vulns, actual_vulns,
                                 f"Vulns: {actual_vulns} < baseline {min_vulns}")
            else:
                result.add_check("endpoint", name, True, min_vulns, actual_vulns,
                                 f"Vulns: {actual_vulns} ≥ baseline {min_vulns}")
        else:
            # Safe-expected: verify no FPs (or at least within threshold)
            fp = run_entry.get("vulns", 0)
            if fp > 0:
                result.add_check("endpoint", name, False, 0, fp,
                                 f"Expected Safe, got {fp} vulns (FP!)")
            else:
                result.add_check("endpoint", name, True, 0, fp, "Expected Safe, no FPs")

    # Check for new endpoints not in manifest (not a regression, but informative)
    for name in sorted(run_eps.keys()):
        if name not in manifest_eps:
            result.add_check("endpoint", name, True, "N/A", "new",
                             f"New endpoint (not in baseline) — consider adding to regression_manifest.json")

    return result


# ── Print Helpers ────────────────────────────────────────────

def print_result(result, run_name):
    """Print formatted regression results."""
    print(f"\n{'='*60}")
    print(f"  REGRESSION CHECK — {run_name}")
    print(f"{'='*60}")
    print(f"  Overall: {'✅ PASSED' if result.passed else '❌ FAILED'}")
    print(f"  Checks: {result.summary['passed']} passed, {result.summary['failed']} failed\n")

    if result.metric_checks:
        print(f"  📊 Metric Thresholds")
        for c in result.metric_checks:
            icon = "✅" if c["passed"] else "❌"
            print(f"    {icon}  {c['message']}")
        print()

    if result.endpoint_checks:
        print(f"  🔍 Per-Endpoint Results")
        for c in result.endpoint_checks:
            icon = "✅" if c["passed"] else "❌"
            print(f"    {icon}  [{c['name']:30s}] {c['message']}")
        print()

    if not result.passed:
        print("  {:─^60}".format(""))
        print(f"  ❌ REGRESSION DETECTED — review failures above")
        fails = [c for c in result.endpoint_checks if not c["passed"]]
        if fails:
            print(f"  Endpoints below baseline: {[c['name'] for c in fails]}")
        print()


# ── CLI ──────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Regression check against golden baseline")
    parser.add_argument("run_id", nargs="?", default=None,
                        help="Run ID (directory in eval/archive/)")
    parser.add_argument("--manifest", type=str, default=None,
                        help="Path to custom regression manifest")
    parser.add_argument("--json", action="store_true",
                        help="JSON output (CI-friendly)")
    parser.add_argument("--generate-manifest", action="store_true",
                        help="Generate regression_manifest.json from this run")
    parser.add_argument("--output", type=str, default=None,
                        help="Save JSON results to file")
    args = parser.parse_args()

    # Resolve the run
    run_dir = resolve_run(args.run_id)

    # ── Generate manifest mode ──
    if args.generate_manifest:
        summary = load_summary(run_dir)
        if not summary:
            sys.exit(1)
        manifest = generate_manifest_from_summary(summary, run_dir.name)
        if args.output:
            output_path = Path(args.output)
        else:
            output_path = DEFAULT_MANIFEST
        output_path.write_text(json.dumps(manifest, indent=2))
        print(f"  ✅ Regression manifest generated: {output_path}")
        print(f"     Source run: {run_dir.name}")
        print(f"     Endpoints:  {len(manifest['endpoints'])}")
        print(f"     Commit this file to version control as the golden baseline.")
        return 0

    # ── Check mode ──
    summary = load_summary(run_dir)
    if not summary:
        sys.exit(1)

    manifest = load_regression_manifest(args.manifest)
    result = check_regression(summary, manifest)

    if args.json:
        output = result.to_dict()
        output["run_id"] = run_dir.name
        print(json.dumps(output, indent=2))
    else:
        print_result(result, run_dir.name)

    # Save to run directory
    results_file = run_dir / "analysis" / "regression.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(result.to_dict(), indent=2))

    # Exit code: 0 = pass, 1 = fail
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
