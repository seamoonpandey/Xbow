"""
eval/_common.py — Shared utilities for all eval analysis and report scripts.

Provides consistent run resolution, data loading, and helper functions
used across metrics, analysis, and report modules.
"""

import json
import sys
from pathlib import Path

ARCHIVE_DIR = Path(__file__).resolve().parent / "archive"


def get_latest_run():
    """Get the most recent run directory containing a summary.json."""
    if not ARCHIVE_DIR.exists():
        print(f"[!] Archive directory not found: {ARCHIVE_DIR}")
        sys.exit(1)
    runs = sorted(ARCHIVE_DIR.iterdir())
    valid = [r for r in runs if (r / "summary.json").exists()]
    if not valid:
        print("[!] No completed runs found in eval/archive/")
        sys.exit(1)
    return valid[-1]


def resolve_run(run_id=None):
    """Resolve a run directory from an optional run_id or get latest."""
    if run_id:
        run_dir = ARCHIVE_DIR / run_id
        if not run_dir.exists():
            print(f"[!] Run not found: {run_dir}")
            sys.exit(1)
    else:
        run_dir = get_latest_run()
    return run_dir


def load_summary(run_dir):
    """Load summary.json from a run directory."""
    summary_file = run_dir / "summary.json"
    if not summary_file.exists():
        print(f"[!] No summary.json found in {run_dir}")
        return None
    with open(summary_file, "r") as f:
        return json.load(f)


def load_portswigger(run_dir):
    """Load portswigger.json from a run directory."""
    ps_file = run_dir / "portswigger.json"
    if not ps_file.exists():
        return None
    with open(ps_file, "r") as f:
        return json.load(f)
