#!/usr/bin/env python3
"""
generate_dataset_manifest.py — Generate dataset_manifest.json with source
metadata for reproducibility.

Output: dataset/dataset_manifest.json

Records:
- Source repo URLs, commit hashes, download dates
- Checksums (SHA-256) for every processed CSV and split file
- Row counts for every file in the pipeline
- Script versions (git commit of each pipeline script)
- Timestamp of generation

Usage:
    python scripts/generate_dataset_manifest.py
"""

import csv
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "dataset"
PROCESSED_DIR = DATASET_DIR / "processed"
SPLITS_DIR = DATASET_DIR / "splits"
RAW_DIR = DATASET_DIR / "raw"


# ── Helpers ────────────────────────────────────────────────────────────────


def _git_sha(path: str | Path) -> str | None:
    """Get the current commit SHA of a git repo at `path`."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def _git_remote_url(path: str | Path) -> str | None:
    """Get the remote origin URL of a git repo at `path`."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def _file_sha256(path: Path) -> str | None:
    """Compute SHA-256 hex digest of a file."""
    if not path.exists():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _row_count(path: Path) -> int | None:
    """Count data rows (lines minus header) of a CSV file."""
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        rows = sum(1 for _ in reader)
    return max(0, rows - 1)  # subtract header


def _script_git_info(script_name: str) -> dict:
    """Get git SHA and date of a script in the repo."""
    script_path = ROOT / script_name
    info = {"sha": None, "date": None}
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H|%aI", "--", str(script_path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            sha, date = result.stdout.strip().split("|")
            info["sha"] = sha
            info["date"] = date
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return info


def _raw_dir_mod_time(path: Path) -> str | None:
    """Get the modification time (ISO-8601) of a raw source directory."""
    if not path.is_dir():
        return None
    try:
        mtime = datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc
        )
        return mtime.isoformat()
    except OSError:
        return None


# ── Manifest collection ────────────────────────────────────────────────────


def collect_source_info() -> list[dict]:
    """Collect metadata for each raw source."""
    sources = [
        {
            "name": "AwesomeXSS",
            "url": "https://github.com/s0md3v/AwesomeXSS",
            "path": "dataset/raw/AwesomeXSS",
        },
        {
            "name": "PayloadsAllTheThings",
            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
            "path": "dataset/raw/PayloadsAllTheThings",
        },
        {
            "name": "XSSGAI",
            "url": "https://github.com/AnonKryptiQuz/XSSGAI",
            "path": "dataset/raw/XSSGAI",
        },
        {
            "name": "PortSwigger XSS Cheat Sheet",
            "url": "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
            "path": "dataset/raw/portswigger_raw.html",
        },
    ]

    results = []
    for src in sources:
        entry = {
            "name": src["name"],
            "url": src["url"],
            "path": src["path"],
        }

        full_path = ROOT / src["path"]

        if "portswigger" in src["name"].lower():
            # HTML file, not a git repo
            if full_path.exists():
                entry["sha256"] = _file_sha256(full_path)
                entry["size_bytes"] = full_path.stat().st_size
                entry["download_date"] = datetime.fromtimestamp(os.path.getmtime(full_path), tz=timezone.utc).isoformat()
            entry["type"] = "downloaded_file"
        else:
            # Git repo
            repo_path = full_path
            if repo_path.is_dir():
                entry["commit_sha"] = _git_sha(repo_path)
                entry["remote_url"] = _git_remote_url(repo_path)
                entry["download_date"] = _raw_dir_mod_time(repo_path)
                entry["file_count"] = len(list(repo_path.rglob("*")))
            entry["type"] = "git_clone"

        results.append(entry)

    return results


def collect_file_artifacts() -> dict[str, dict]:
    """Collect checksums and row counts for all processed/split files."""
    files = {}

    # Processed CSVs
    for csv_file in sorted(PROCESSED_DIR.glob("*.csv")):
        rel = str(csv_file.relative_to(ROOT))
        files[rel] = {
            "sha256": _file_sha256(csv_file),
            "rows": _row_count(csv_file),
            "size_bytes": csv_file.stat().st_size,
        }

    # Split CSVs
    for csv_file in sorted(SPLITS_DIR.glob("*.csv")):
        rel = str(csv_file.relative_to(ROOT))
        files[rel] = {
            "sha256": _file_sha256(csv_file),
            "rows": _row_count(csv_file),
            "size_bytes": csv_file.stat().st_size,
        }

    # Split TXT payload files
    for txt_file in sorted(SPLITS_DIR.glob("*.txt")):
        rel = str(txt_file.relative_to(ROOT))
        lines = len(txt_file.read_text().strip().splitlines()) if txt_file.exists() else 0
        files[rel] = {
            "sha256": _file_sha256(txt_file),
            "rows": lines,
            "size_bytes": txt_file.stat().st_size,
        }

    # Ranker training JSONL
    ranker_jsonl = DATASET_DIR / "ranker_training" / "ranker_training_samples.jsonl"
    if ranker_jsonl.exists():
        rel = str(ranker_jsonl.relative_to(ROOT))
        files[rel] = {
            "sha256": _file_sha256(ranker_jsonl),
            "rows": sum(1 for _ in open(ranker_jsonl) if _.strip()),
            "size_bytes": ranker_jsonl.stat().st_size,
        }

    return files


def collect_script_versions() -> dict[str, dict]:
    """Get git info for each pipeline script."""
    scripts = [
        "dataset/collect_payloads.py",
        "dataset/collect_portswigger.py",
        "dataset/label_contexts.py",
        "dataset/generate_synthetic.py",
        "dataset/finalize_dataset.py",
        "scripts/dataset_stats.py",
        "scripts/generate_dataset_manifest.py",
        "dataset/events.py",
        "dataset/tags.py",
    ]
    return {
        s: _script_git_info(s)
        for s in scripts
    }


# ── Main ────────────────────────────────────────────────────────────────────


def main():
    print("Collecting source repository metadata...")
    sources = collect_source_info()

    print("Scanning processed artifacts...")
    artifacts = collect_file_artifacts()

    print("Resolving script versions...")
    script_versions = collect_script_versions()

    # Pipeline ordering hints
    pipeline_order = [
        "dataset/collect_payloads.py",
        "dataset/collect_portswigger.py",
        "dataset/label_contexts.py",
        "dataset/generate_synthetic.py",
        "dataset/finalize_dataset.py",
        "scripts/dataset_stats.py",
        "scripts/generate_dataset_manifest.py",
    ]

    manifest = {
        "manifest_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_repo_sha": _git_sha(ROOT),
        "sources": sources,
        "scripts": script_versions,
        "pipeline_order": pipeline_order,
        "artifacts": artifacts,
        "notes": [
            "dataset/raw/ is gitignored — raw sources exist only locally.",
            'Run "make dataset" to rebuild all processed/split files from raw sources.',
            'Run "make dataset-report" to regenerate dataset_stats.py output.',
            "PortSwigger source is an HTML file (not a git repo); checksum proven here.",
            "Commit SHAs for raw sources are from local clones and may differ from origin HEAD.",
        ],
    }

    out_path = DATASET_DIR / "dataset_manifest.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    print(f"\n[DONE] Manifest written to {out_path}")
    print(f"  {len(sources)} sources documented")
    print(f"  {len(artifacts)} file artifacts checksummed")
    print(f"  {len(script_versions)} script versions recorded")


if __name__ == "__main__":
    main()
