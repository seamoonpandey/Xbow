#!/usr/bin/env python3
"""
dataset_stats.py — Reproducible dataset statistics for the RedSentinel XSS corpus.

Usage:
    python scripts/dataset_stats.py

This script reads the actual CSV files on disk and reports exact, reproducible
numbers for every stage of the dataset pipeline.  It is the authoritative source
for dataset size claims — any report citing a payload count MUST reference the
output of this script.

Pipeline overview:
    collect_payloads.py (raw)    → processed/all_payloads_raw.csv      (~19k rows)
    collect_portswigger.py       → processed/portswigger_payloads.csv  (~600 rows)
    label_contexts.py            → processed/payloads_labeled.csv      (~19k rows)
    generate_synthetic.py        → processed/synthetic_payloads.csv    (~43k rows)
    finalize_dataset.py          → splits/train.csv + val.csv + test.csv

    (Exact counts are computed and printed at runtime below.)
"""

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

# ── Paths ──────────────────────────────────────────────────────────────────────
RAW_CSV      = ROOT / "dataset" / "processed" / "all_payloads_raw.csv"
PORT_CSV     = ROOT / "dataset" / "processed" / "portswigger_payloads.csv"
LABELED_CSV  = ROOT / "dataset" / "processed" / "payloads_labeled.csv"
SYNTHETIC_CSV = ROOT / "dataset" / "processed" / "synthetic_payloads.csv"
TRAIN_CSV    = ROOT / "dataset" / "splits" / "train.csv"
VAL_CSV      = ROOT / "dataset" / "splits" / "val.csv"
TEST_CSV     = ROOT / "dataset" / "splits" / "test.csv"
RANKER_JSONL = ROOT / "dataset" / "ranker_training" / "ranker_training_samples.jsonl"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_csv(path: Path, required: set[str] | None = None) -> pd.DataFrame:
    """Load a CSV, returning an empty DataFrame if missing."""
    if not path.exists():
        print(f"  [WARN] File not found: {path}", file=sys.stderr)
        return pd.DataFrame()
    df = pd.read_csv(path, on_bad_lines="skip")
    if required is not None and not required.issubset(set(df.columns)):
        print(f"  [WARN] {path.name}: missing columns {required - set(df.columns)}", file=sys.stderr)
        return pd.DataFrame()
    return df


def _sep(title: str):
    """Print a section separator."""
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def _fmt(n: int) -> str:
    """Format integer with thousands separator."""
    return f"{n:>10,}"


# ── Main report ────────────────────────────────────────────────────────────────

def main():
    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║        RedSentinel XSS Corpus — Reproducible Dataset Statistics     ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(f"  Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Script:    scripts/dataset_stats.py")
    print()

    # ── 1. Raw collection ──────────────────────────────────────────────────────
    _sep("1. Raw Collection")

    raw = _load_csv(RAW_CSV, {"payload"})
    n_raw = len(raw)
    print(f"  all_payloads_raw.csv        : {_fmt(n_raw)}  payloads (from AwesomeXSS, XSSGAI, PayloadsAllTheThings)")
    print(f"    (line count minus header  : {_fmt(n_raw)} payloads)")

    port = _load_csv(PORT_CSV, {"payload"})
    n_port = len(port)
    print(f"  portswigger_payloads.csv    : {_fmt(n_port)}  payloads (from PortSwigger cheat sheet)")

    # ── 2. Labeling stage ──────────────────────────────────────────────────────
    _sep("2. Labeling Stage")

    labeled = _load_csv(LABELED_CSV, {"payload", "context", "severity"})
    n_labeled = len(labeled)
    print(f"  payloads_labeled.csv        : {_fmt(n_labeled)}  labeled payloads")

    if "source" not in labeled.columns:
        # Older payloads_labeled.csv doesn't have source column
        print(f"    (source column not present — all treated as 'real')")

    # Count unique payloads in labeled set
    n_unique_labeled = labeled["payload"].nunique() if not labeled.empty else 0
    print(f"  Unique payload texts        : {_fmt(n_unique_labeled)}")

    # PortSwigger contribution
    # PortSwigger is an INDEPENDENT script (collect_portswigger.py) — its output
    # is NOT automatically merged into all_payloads_raw.csv or payloads_labeled.csv.
    # It exists as a separate reference/verification set.
    if port.empty:
        print(f"  PortSwigger CSV: not found — skipped")
    elif labeled.empty:
        print(f"  PortSwigger CSV: {_fmt(n_port)} payloads (labeled CSV not found for overlap check)")
    else:
        ps_in_labeled = labeled[labeled["payload"].isin(port["payload"])]
        overlapping = len(ps_in_labeled)
        unique_to_port = n_port - overlapping
        print(f"  PortSwigger payloads          : {_fmt(n_port)}")
        print(f"    ├─ Also in labeled set      : {_fmt(overlapping)}")
        print(f"    └─ PortSwigger-only         : {_fmt(unique_to_port)}")

    # ── 3. Synthetic generation ────────────────────────────────────────────────
    _sep("3. Synthetic Generation")

    synthetic = _load_csv(SYNTHETIC_CSV, {"payload"})
    n_synthetic = len(synthetic)
    print(f"  synthetic_payloads.csv      : {_fmt(n_synthetic)}  synthetic payloads")
    if not synthetic.empty:
        print(f"  Unique synthetic payloads  : {_fmt(synthetic['payload'].nunique())}")

    # ── 4. Finalization & Deduplication ────────────────────────────────────────
    _sep("4. Finalization & Deduplication")

    # Merge labeled + synthetic (as finalize_dataset.py does)
    if not labeled.empty and not synthetic.empty:
        labeled_stage = labeled.copy()
        synthetic_stage = synthetic.copy()

        labeled_stage["source"] = labeled_stage.get("source", "real")
        synthetic_stage["source"] = "synthetic"

        # Add missing columns for synthetic
        if "technique" not in synthetic_stage.columns:
            synthetic_stage["technique"] = "synthetic"
        if "severity" not in synthetic_stage.columns:
            # apply the same severity logic as finalize_dataset.py
            synthetic_stage["severity"] = "medium"
        if "length" not in synthetic_stage.columns:
            synthetic_stage["length"] = synthetic_stage["payload"].str.len()

        combined = pd.concat([labeled_stage, synthetic_stage], ignore_index=True)
        print(f"  Combined (labeled + synthetic) : {_fmt(len(combined))}")

        before_dedup = len(combined)
        combined = combined.drop_duplicates(subset=["payload"])
        n_dup = before_dedup - len(combined)
        print(f"  Duplicates removed             : {_fmt(n_dup)}")
        print(f"  After deduplication            : {_fmt(len(combined))}")
    else:
        print("  [SKIP] — missing labeled or synthetic CSV")
        combined = pd.DataFrame()

    # ── 5. Validity filter ─────────────────────────────────────────────────────
    if not combined.empty:
        _sep("5. Validity Filter Applied (finalize_dataset.py)")

        import re

        XSS_PATTERNS = [
            r'<\s*script', r'on\w+\s*=', r'javascript\s*:', r'data\s*:\s*text/html',
            r'<\s*svg', r'<\s*img', r'<\s*iframe', r'<\s*body',
            r'alert\s*[\(`]', r'prompt\s*[\(`]', r'confirm\s*[\(`]',
            r'document\.', r'eval\s*\(', r'window\.', r'innerHTML',
            r'String\.fromCharCode', r'setTimeout', r'location\s*=',
            r'&#', r'%3[cC]',
            r'\{\{.*?\}\}', r'\$\{.*?\}', r'<%.*?%>', r'#\{.*?\}',
        ]

        def is_valid(p):
            if not isinstance(p, str):
                return False
            if not (5 < len(p) < 2000):
                return False
            return any(re.search(pat, p, re.IGNORECASE) for pat in XSS_PATTERNS)

        before_filter = len(combined)
        combined = combined[combined["payload"].apply(is_valid)].copy()
        n_invalid = before_filter - len(combined)
        print(f"  Before validity filter         : {_fmt(before_filter)}")
        print(f"  Removed (invalid/out of range) : {_fmt(n_invalid)}")
        print(f"  After validity filter          : {_fmt(len(combined))}")

        # Drop unknown labels (same as finalize_dataset.py)
        VALID_CONTEXTS = {
            "script_injection", "event_handler", "js_uri", "tag_injection",
            "template_injection", "dom_sink", "attribute_escape", "attribute", "generic",
        }
        VALID_SEVERITIES = {"low", "medium", "high"}

        before_label = len(combined)
        combined = combined[
            combined["context"].isin(VALID_CONTEXTS) &
            combined["severity"].isin(VALID_SEVERITIES)
        ]
        n_unknown_labels = before_label - len(combined)
        print(f"  Removed (unknown labels)       : {_fmt(n_unknown_labels)}")
        print(f"  After label filtering          : {_fmt(len(combined))}")

        TOTAL_STAGE4 = len(combined)
        print(f"\n  ► FINAL CURATED PAYLOAD COUNT : {_fmt(TOTAL_STAGE4)}")
    else:
        TOTAL_STAGE4 = 0

    # ── 6. Train / Validation / Test Splits ────────────────────────────────────
    _sep("6. Train / Validation / Test Splits")

    train = _load_csv(TRAIN_CSV)
    val = _load_csv(VAL_CSV)
    test = _load_csv(TEST_CSV)

    n_train = len(train)
    n_val = len(val)
    n_test = len(test)
    n_total_splits = n_train + n_val + n_test

    print(f"  Train split      : {_fmt(n_train)}  ({n_train / n_total_splits * 100:.1f}%)" if n_total_splits else "  (no data)")
    print(f"  Validation split : {_fmt(n_val)}  ({n_val / n_total_splits * 100:.1f}%)" if n_total_splits else "")
    print(f"  Test split       : {_fmt(n_test)}  ({n_test / n_total_splits * 100:.1f}%)" if n_total_splits else "")
    print(f"  ─────────────────────────────────────")
    print(f"  Total across splits : {_fmt(n_total_splits)}")

    # Check if split totals match the pipeline count
    if TOTAL_STAGE4 > 0 and n_total_splits > 0 and TOTAL_STAGE4 != n_total_splits:
        diff = abs(TOTAL_STAGE4 - n_total_splits)
        print(f"\n  ⚠  Split total ({_fmt(n_total_splits)}) differs from pipeline")
        print(f"     count ({_fmt(TOTAL_STAGE4)}) by {_fmt(diff)}.")
        print(f"     Split CSVs may be stale — re-run finalize_dataset.py to")
        print(f"     regenerate them from current processed CSVs.")

    # ── 7. Context / Severity Distribution ─────────────────────────────────────
    _sep("7. Class Distribution (from split CSVs)")

    if not train.empty and not val.empty and not test.empty:
        for df in [train, val, test]:
            if "split" not in df.columns:
                # Infer from filename
                pass

        train["_split"] = "train"
        val["_split"] = "val"
        test["_split"] = "test"
        all_splits = pd.concat([train, val, test], ignore_index=True)

        # Context distribution
        print("\n  ── Per Context Class ──")
        ctx_counts = all_splits["context"].value_counts()
        for ctx, count in ctx_counts.items():
            print(f"    {ctx:<22} {_fmt(count)}  ({count / len(all_splits) * 100:.1f}%)")

        # Severity distribution
        print("\n  ── Per Severity ──")
        sev_counts = all_splits["severity"].value_counts()
        for sev in ["high", "medium", "low"]:
            count = sev_counts.get(sev, 0)
            print(f"    {sev:<10} {_fmt(count)}  ({count / len(all_splits) * 100:.1f}%)")

        # Source contribution
        print("\n  ── Per Source ──")
        if "source" in all_splits.columns:
            src_counts = all_splits["source"].value_counts()
            for src, count in src_counts.items():
                print(f"    {src:<10} {_fmt(count)}  ({count / len(all_splits) * 100:.1f}%)")
        else:
            print("    (source column not available in split CSVs)")
    else:
        print("  (split CSVs not found)")

    # ── 8. Executable / Verified Payloads ──────────────────────────────────────
    _sep("8. Executable / Verified Payloads (from ranker training)")

    n_ranker = 0
    n_executed = 0
    n_dialog = 0
    n_reflected = 0
    n_exact_match = 0
    n_success = 0

    if RANKER_JSONL.exists():
        samples = []
        with open(RANKER_JSONL) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        samples.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        n_ranker = len(samples)

        n_success = sum(1 for s in samples if s.get("success"))
        n_executed = sum(1 for s in samples if s.get("executed"))
        n_dialog = sum(1 for s in samples if s.get("dialog_triggered"))
        n_reflected = sum(1 for s in samples if s.get("reflected"))
        n_exact_match = sum(1 for s in samples if s.get("exact_match"))

        print(f"  Ranker training samples        : {_fmt(n_ranker)}")
        print(f"    ├─ Reflected in response      : {_fmt(n_reflected)}  ({n_reflected / n_ranker * 100:.1f}%)")
        print(f"    ├─ Exact-match reflection     : {_fmt(n_exact_match)}  ({n_exact_match / n_ranker * 100:.1f}%)")
        print(f"    ├─ Browser-executed           : {_fmt(n_executed)}  ({n_executed / n_ranker * 100:.1f}%)")
        print(f"    ├─ Dialog triggered (alert)   : {_fmt(n_dialog)}  ({n_dialog / n_ranker * 100:.1f}%)")
        print(f"    └─ Successful (combined flag) : {_fmt(n_success)}  ({n_success / n_ranker * 100:.1f}%)")
    else:
        print(f"  (ranker training data not found at {RANKER_JSONL})")

    # ── 9. Summary ─────────────────────────────────────────────────────────────
    _sep("9. Summary — Authoritative Payload Bank Size")

    print()
    if TOTAL_STAGE4 > 0:
        # NOTE: PortSwigger is a separate/independent source, not in the main pipeline.
        # The main pipeline is: labeled (from raw collection) + synthetic → final.
        print(f"  Pipeline flow (main):")
        print(f"    labeled ({_fmt(n_labeled)}) + synthetic ({_fmt(n_synthetic)})")
        print(f"    → combined → dedup → validity filter → label filter → split")
        print(f"    (PortSwigger is an independent reference source, not part of this chain)")
        print()
        print(f"  ► Final curated payload bank  :  {_fmt(TOTAL_STAGE4)}")
        print()
        print(f"  ► Train / Val / Test          :  {_fmt(n_train)} / {_fmt(n_val)} / {_fmt(n_test)}")
        print(f"    (total across splits        :  {_fmt(n_total_splits)})")
        print()
        print(f"  ► Browser-verified (executed) :  {_fmt(n_executed) if RANKER_JSONL.exists() else 'N/A'}")
        print(f"  ► Ranker training samples     :  {_fmt(n_ranker) if RANKER_JSONL.exists() else 'N/A'}")
    else:
        print("  (Could not compute pipeline — CSV files may not exist)")
        print("  Run the pipeline scripts in order:")
        print("    1. dataset/collect_payloads.py")
        print("    2. dataset/collect_portswigger.py")
        print("    3. dataset/label_contexts.py")
        print("    4. dataset/generate_synthetic.py")
        print("    5. dataset/finalize_dataset.py")

    print()
    print("  Note: Use \"approximately 59K+\" for the curated payload-bank size")
    print("  unless this script's reproducible output proves a more exact number.")
    print()


if __name__ == "__main__":
    main()
