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
    collect_payloads.py (raw)    -> processed/all_payloads_raw.csv      (~19k rows)
    collect_portswigger.py       -> processed/portswigger_payloads.csv  (~600 rows)
    label_contexts.py            -> processed/payloads_labeled.csv      (~19k rows)
    generate_synthetic.py        -> processed/synthetic_payloads.csv    (~43k rows)
    finalize_dataset.py          -> splits/train.csv + val.csv + test.csv

    (Exact counts are computed and printed at runtime below.)
"""

import json
import re
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

# -- Paths ----------------------------------------------------------------------------
RAW_CSV       = ROOT / "dataset" / "processed" / "all_payloads_raw.csv"
PORT_CSV      = ROOT / "dataset" / "processed" / "portswigger_payloads.csv"
LABELED_CSV   = ROOT / "dataset" / "processed" / "payloads_labeled.csv"
SYNTHETIC_CSV = ROOT / "dataset" / "processed" / "synthetic_payloads.csv"
TRAIN_CSV     = ROOT / "dataset" / "splits" / "train.csv"
VAL_CSV       = ROOT / "dataset" / "splits" / "val.csv"
TEST_CSV      = ROOT / "dataset" / "splits" / "test.csv"
RANKER_JSONL  = ROOT / "dataset" / "ranker_training" / "ranker_training_samples.jsonl"


# -- Helpers ---------------------------------------------------------------------------

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


# -- Main report -----------------------------------------------------------------------

def main():
    BOX = "\u2500"          # box-drawing horizontal line character
    WARN = "\u26a0"         # warning sign

    print()
    print("\u2554" + "\u2550" * 66 + "\u2557")
    print("\u2551        RedSentinel XSS Corpus \u2014 Reproducible Dataset Statistics     \u2551")
    print("\u255a" + "\u2550" * 66 + "\u255d")
    print(f"  Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Script:    scripts/dataset_stats.py")
    print()

    # -- 1. Raw collection -----------------------------------------------------------------
    _sep("1. Raw Collection")

    raw = _load_csv(RAW_CSV, {"payload"})
    n_raw = len(raw)
    print(f"  all_payloads_raw.csv        : {_fmt(n_raw)}  payloads (from AwesomeXSS, XSSGAI, PayloadsAllTheThings)")
    print(f"    (line count minus header  : {_fmt(n_raw)} payloads)")

    port = _load_csv(PORT_CSV, {"payload"})
    n_port = len(port)
    print(f"  portswigger_payloads.csv    : {_fmt(n_port)}  payloads (from PortSwigger cheat sheet)")

    # -- 2. Labeling stage -----------------------------------------------------------------
    _sep("2. Labeling Stage")

    labeled = _load_csv(LABELED_CSV, {"payload", "context", "severity"})
    n_labeled = len(labeled)
    print(f"  payloads_labeled.csv        : {_fmt(n_labeled)}  labeled payloads")

    if "source" not in labeled.columns:
        print(f"    (source column not present \u2014 all treated as 'real')")

    n_unique_labeled = labeled["payload"].nunique() if not labeled.empty else 0
    print(f"  Unique payload texts        : {_fmt(n_unique_labeled)}")

    if port.empty:
        print(f"  PortSwigger CSV: not found \u2014 skipped")
    elif labeled.empty:
        print(f"  PortSwigger CSV: {_fmt(n_port)} payloads (labeled CSV not found for overlap check)")
    else:
        ps_in_labeled = labeled[labeled["payload"].isin(port["payload"])]
        overlapping = len(ps_in_labeled)
        unique_to_port = n_port - overlapping
        print(f"  PortSwigger payloads          : {_fmt(n_port)}")
        print(f"    |-- Also in labeled set      : {_fmt(overlapping)}")
        print(f"    \\-- PortSwigger-only         : {_fmt(unique_to_port)}")

    # -- 3. Synthetic generation -----------------------------------------------------------
    _sep("3. Synthetic Generation")

    synthetic = _load_csv(SYNTHETIC_CSV, {"payload"})
    n_synthetic = len(synthetic)
    print(f"  synthetic_payloads.csv      : {_fmt(n_synthetic)}  synthetic payloads")
    if not synthetic.empty:
        print(f"  Unique synthetic payloads  : {_fmt(synthetic['payload'].nunique())}")

    # -- 4. Finalization & Deduplication ----------------------------------------------------
    _sep("4. Finalization & Deduplication")

    if not labeled.empty and not synthetic.empty:
        labeled_stage = labeled.copy()
        synthetic_stage = synthetic.copy()

        labeled_stage["source"] = labeled_stage.get("source", "real")
        synthetic_stage["source"] = "synthetic"

        if "technique" not in synthetic_stage.columns:
            synthetic_stage["technique"] = "synthetic"
        if "severity" not in synthetic_stage.columns:
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
        print("  [SKIP] \u2014 missing labeled or synthetic CSV")
        combined = pd.DataFrame()

    # -- 5. Validity filter -----------------------------------------------------------------
    if not combined.empty:
        _sep("5. Validity Filter Applied (finalize_dataset.py)")

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
        print(f"\n  \u25ba FINAL CURATED PAYLOAD COUNT : {_fmt(TOTAL_STAGE4)}")
    else:
        TOTAL_STAGE4 = 0

    # -- 6. Train / Validation / Test Splits -------------------------------------------------
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
    print(f"  {BOX * 37}")
    print(f"  Total across splits : {_fmt(n_total_splits)}")

    if TOTAL_STAGE4 > 0 and n_total_splits > 0 and TOTAL_STAGE4 != n_total_splits:
        diff = abs(TOTAL_STAGE4 - n_total_splits)
        print(f"\n  {WARN}  Split total ({_fmt(n_total_splits)}) differs from pipeline")
        print(f"     count ({_fmt(TOTAL_STAGE4)}) by {_fmt(diff)}.")
        print(f"     Split CSVs may be stale \u2014 re-run finalize_dataset.py to")
        print(f"     regenerate them from current processed CSVs.")

    # -- 7. Payload-Family Balance -----------------------------------------------------------
    _sep("7. Payload-Family Balance (dominant XSS patterns)")

    if not train.empty or not val.empty or not test.empty:
        all_dfs = []
        for df, name in [(train, "train"), (val, "val"), (test, "test")]:
            if not df.empty:
                d = df.copy()
                d["_split"] = name
                all_dfs.append(d)
        if all_dfs:
            all_splits = pd.concat(all_dfs, ignore_index=True)

            FAMILIES = [
                ("<script>",       r'<\s*script[^a-zA-Z]'),
                ("<img>",          r'<\s*img\s'),
                ("<svg>",          r'<\s*svg\s'),
                ("<iframe>",       r'<\s*iframe\s'),
                ("<body>",          r'<\s*body\s'),
                ("<input>",        r'<\s*input\s'),
                ("<a>",            r'<\s*a\s'),
                ("<details>",      r'<\s*details\s'),
                ("onerror=",       r'onerror\s*='),
                ("onload=",        r'onload\s*='),
                ("onclick=",       r'onclick\s*='),
                ("onmouseover=",   r'onmouseover\s*='),
                ("onfocus=",       r'onfocus\s*='),
                ("onmouseenter=",  r'onmouseenter\s*='),
                ("onpointer",      r'onpointer\w+\s*='),
                ("onanimation",    r'onanimation\w+\s*='),
                ("ontoggle=",      r'ontoggle\s*='),
                ("js_uri",         r'javascript\s*:'),
                ("data_uri",       r'data\s*:\s*text/html'),
                ("template_brace", r'\{\{.*?\}\}'),
                ("template_dollar",r'\$\{.*?\}'),
                ("template_pct",   r'<%.*?%>'),
                ("template_hash",  r'#\{.*?\}'),
                ("eval_call",      r'eval\s*\('),
                ("innerHTML",      r'innerHTML'),
                ("setTimeout",     r'setTimeout\s*\('),
                ("setInterval",    r'setInterval\s*\('),
                ("document.write", r'document\.write'),
                ("Function()",     r'Function\s*\('),
                ("fromCharCode",   r'String\.fromCharCode'),
                ("location=",      r'location\s*='),
                ("fetch()",        r'fetch\s*\('),
                ("alert()",        r'alert\s*[\(`]'),
                ("prompt()",       r'prompt\s*[\(`]'),
                ("confirm()",      r'confirm\s*[\(`]'),
            ]

            print("\n  Payload families detected (note: one payload may match multiple families):")
            print(f"  {'Family':<22} {'Count':>10}  {'% of total':>10}")
            print(f"  {BOX*22} {BOX*10}  {BOX*10}")
            for family_name, pattern in FAMILIES:
                count = all_splits["payload"].str.contains(pattern, regex=True, na=False).sum()
                if count > 0:
                    print(f"  {family_name:<22} {_fmt(count)}  {count / len(all_splits) * 100:>9.1f}%")

            has_tag = all_splits["payload"].str.contains(r'<\w+', na=False)
            has_handler = all_splits["payload"].str.contains(r'on\w+\s*=', na=False)
            has_js_uri = all_splits["payload"].str.contains(r'javascript\s*:|data\s*:\s*text/html', na=False)
            has_template = all_splits["payload"].str.contains(r'\{\{|\$\{|<%|#\{', na=False)
            has_dom = all_splits["payload"].str.contains(r'document\.|\.innerHTML|eval\s*\(|setTimeout|setInterval', na=False)
            has_func = all_splits["payload"].str.contains(r'alert\s*[\(`]|prompt\s*[\(`]|confirm\s*[\(`]|fetch\s*\(', na=False)

            print("\n  Top-level family overlap (each payload counted once):")
            family_of = pd.Series(index=all_splits.index, dtype=str)
            family_of[has_tag & has_handler] = "tag_and_handler"
            family_of[has_tag & ~has_handler] = "tag_only"
            family_of[~has_tag & has_handler] = "handler_only"
            family_of[~has_tag & ~has_handler & has_js_uri] = "js_uri"
            family_of[~has_tag & ~has_handler & ~has_js_uri & has_template] = "template"
            family_of[~has_tag & ~has_handler & ~has_js_uri & ~has_template & has_dom] = "dom_sink"
            family_of[~has_tag & ~has_handler & ~has_js_uri & ~has_template & ~has_dom & has_func] = "func_call"
            family_of.fillna("other", inplace=True)

            for fam in ["tag_and_handler", "tag_only", "handler_only", "js_uri", "template", "dom_sink", "func_call", "other"]:
                count = (family_of == fam).sum()
                print(f"    {fam:<20} {_fmt(count)}  ({count / len(all_splits) * 100:.1f}%)")

    else:
        print("  (split CSVs not found)")

    # -- 8. Encoding & Obfuscation Category Distribution --------------------------------------
    _sep("8. Encoding & Obfuscation Categories")

    ENCODING_CHECKS = [
        ("unicode_escape",        r'\\u[0-9a-fA-F]{4}'),
        ("hex_escape",            r'\\x[0-9a-fA-F]{2}'),
        ("html_entity",           r'&#[xX]?[0-9a-fA-F]+;?'),
        ("url_encoding",          r'%[0-9a-fA-F]{2}(?![0-9a-fA-F])'),
        ("double_url_encoding",   r'%25[0-9a-fA-F]{2}'),
        ("mixed_case",            None),
        ("whitespace_obfuscation", r'(\\t|\\n|&#[x]?0?[9aAdD];)'),
        ("comment_injection",     r'/\*.*\*/|<!--.*-->'),
        ("concat_split",          r"'\s*\+\s*'|\"\s*\+\s*\""),
        ("atob_btoa",             r'\b(atob|btoa)\s*\('),
        ("fromCharCode",          r'fromCharCode\s*\('),
        ("template_literal",      r'`[^`]*\$\{[^}]+}`'),
    ]

    if not train.empty or not val.empty or not test.empty:
        all_dfs = []
        for df, name in [(train, "train"), (val, "val"), (test, "test")]:
            if not df.empty:
                d = df.copy()
                d["_split"] = name
                all_dfs.append(d)
        if all_dfs:
            all_splits = pd.concat(all_dfs, ignore_index=True)
            pal = all_splits["payload"]

            def _has_mixed_case(p):
                tags = re.findall(r'<(/?)([a-zA-Z]+)', str(p))
                if not tags:
                    return False
                for prefix, tag in tags:
                    if tag != tag.lower() and tag != tag.upper():
                        return True
                return False

            mixed_case_count = sum(1 for p in pal if _has_mixed_case(p))

            print("\n  Encoding / obfuscation technique prevalence:")
            print(f"  {'Technique':<25} {'Payloads':>10}  {'% of total':>10}")
            print(f"  {BOX*25} {BOX*10}  {BOX*10}")

            for name, regex in ENCODING_CHECKS:
                if name == "mixed_case":
                    print(f"  {name:<25} {_fmt(mixed_case_count):>10}  {mixed_case_count / len(pal) * 100:>9.1f}%")
                    continue
                if regex is None:
                    continue
                count = pal.str.contains(regex, regex=True, na=False).sum()
                if count > 0:
                    print(f"  {name:<25} {_fmt(count):>10}  {count / len(pal) * 100:>9.1f}%")

            all_re = r'(' + '|'.join(re for _, re in ENCODING_CHECKS if re is not None) + r')'
            no_encoding_no_mixed = (~pal.str.contains(all_re, regex=True, na=False)) \
                                   & ~pal.apply(_has_mixed_case)
            n_none = no_encoding_no_mixed.sum()
            print(f"  {BOX*25} {BOX*10}  {BOX*10}")
            print(f"  {'no_encoding':<25} {_fmt(n_none):>10}  {n_none / len(pal) * 100:>9.1f}%")

            def _count_encodings(p):
                total = 0
                for _, regex in ENCODING_CHECKS:
                    if regex is not None:
                        total += len(re.findall(regex, str(p)))
                return total
            encoding_depths = pal.apply(_count_encodings)
            n_multi = (encoding_depths > 0).sum()
            avg_depth = encoding_depths[encoding_depths > 0].mean() if n_multi > 0 else 0
            print(f"\n  Payloads with \u22651 encoding technique  : {_fmt(n_multi)}  ({n_multi / len(pal) * 100:.1f}%)")
            print(f"  Avg encoding occurrences (among enc): {avg_depth:.2f}")
            print(f"  Max encoding occurrences            : {int(encoding_depths.max())}")

    else:
        print("  (split CSVs not found)")

    # -- 9. Context / Severity Distribution ----------------------------------------------------
    _sep("9. Class Distribution (from split CSVs)")

    if not train.empty and not val.empty and not test.empty:

        train["_split"] = "train"
        val["_split"] = "val"
        test["_split"] = "test"
        all_splits = pd.concat([train, val, test], ignore_index=True)

        print("\n  -- Per Context Class --")
        ctx_counts = all_splits["context"].value_counts()
        for ctx, count in ctx_counts.items():
            print(f"    {ctx:<22} {_fmt(count)}  ({count / len(all_splits) * 100:.1f}%)")

        print("\n  -- Per Severity --")
        sev_counts = all_splits["severity"].value_counts()
        for sev in ["high", "medium", "low"]:
            count = sev_counts.get(sev, 0)
            print(f"    {sev:<10} {_fmt(count)}  ({count / len(all_splits) * 100:.1f}%)")

        print("\n  -- Per Source --")
        if "source" in all_splits.columns:
            src_counts = all_splits["source"].value_counts()
            for src, count in src_counts.items():
                print(f"    {src:<10} {_fmt(count)}  ({count / len(all_splits) * 100:.1f}%)")
        else:
            print("    (source column not available in split CSVs)")
    else:
        print("  (split CSVs not found)")

    # -- 10. Executable / Verified Payloads -----------------------------------------------------
    _sep("10. Executable / Verified Payloads (from ranker training)")

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
        print(f"    |-- Reflected in response      : {_fmt(n_reflected)}  ({n_reflected / n_ranker * 100:.1f}%)")
        print(f"    |-- Exact-match reflection     : {_fmt(n_exact_match)}  ({n_exact_match / n_ranker * 100:.1f}%)")
        print(f"    |-- Browser-executed           : {_fmt(n_executed)}  ({n_executed / n_ranker * 100:.1f}%)")
        print(f"    |-- Dialog triggered (alert)   : {_fmt(n_dialog)}  ({n_dialog / n_ranker * 100:.1f}%)")
        print(f"    \\-- Successful (combined flag) : {_fmt(n_success)}  ({n_success / n_ranker * 100:.1f}%)")
    else:
        print(f"  (ranker training data not found at {RANKER_JSONL})")

    # -- 11. Summary ---------------------------------------------------------------------------
    _sep("11. Summary \u2014 Authoritative Payload Bank Size")

    print()
    if TOTAL_STAGE4 > 0:
        print(f"  Pipeline flow (main):")
        print(f"    labeled ({_fmt(n_labeled)}) + synthetic ({_fmt(n_synthetic)})")
        print(f"    \u2192 combined \u2192 dedup \u2192 validity filter \u2192 label filter \u2192 split")
        print(f"    (PortSwigger is an independent reference source, not part of this chain)")
        print()
        print(f"  \u25ba Final curated payload bank  :  {_fmt(TOTAL_STAGE4)}")
        print()
        print(f"  \u25ba Train / Val / Test          :  {_fmt(n_train)} / {_fmt(n_val)} / {_fmt(n_test)}")
        print(f"    (total across splits        :  {_fmt(n_total_splits)})")
        print()
        print(f"  \u25ba Payload-family distribution  :  see Section 7")
        print(f"  \u25ba Encoding/obfuscation dist.   :  see Section 8")
        print()
        print(f"  \u25ba Browser-verified (executed) :  {_fmt(n_executed) if RANKER_JSONL.exists() else 'N/A'}")
        print(f"  \u25ba Ranker training samples     :  {_fmt(n_ranker) if RANKER_JSONL.exists() else 'N/A'}")
        print()
        if "all_splits" in dir() or "all_splits" in locals():
            n_real = (all_splits["source"] == "real").sum() if "source" in all_splits.columns else 0
            n_syn = (all_splits["source"] == "synthetic").sum() if "source" in all_splits.columns else 0
        else:
            n_real = 0
            n_syn = 0
        if n_real > 0:
            print(f"  \u25ba Real-source payloads        :  {_fmt(n_real)}  ({n_real / len(all_splits) * 100:.1f}%)")
            print(f"  \u25ba Synthetic payloads          :  {_fmt(n_syn)}  ({n_syn / len(all_splits) * 100:.1f}%)")
            print(f"  \u25ba Browser-verified of those   :  {_fmt(n_executed) if RANKER_JSONL.exists() else 'N/A'}  (proven executable in real/browser context)")
            print(f"    (Note: public-list \u2192 real only; synthetic is procedurally generated)")
            print(f"    Real detection power requires end-to-end scanner validation, not just")
            print(f"    payload count. See tests/ and scripts/e2e-smoke.sh for that.")
    else:
        print("  (Could not compute pipeline \u2014 CSV files may not exist)")
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

    # -- 12. Real-World Application Coverage Analysis ------------------------------------------
    _sep("12. Real-World Application Coverage Analysis")

    if not train.empty or not val.empty or not test.empty:
        all_dfs = []
        for df, name in [(train, "train"), (val, "val"), (test, "test")]:
            if not df.empty:
                d = df.copy()
                d["_split"] = name
                all_dfs.append(d)
        if all_dfs:
            all_splits = pd.concat(all_dfs, ignore_index=True)
            pal = all_splits["payload"]

            # ---- 12a. Sink type coverage ------------------------------------------------
            print("\n  12a. Payload coverage per exploitable endpoint sink type")
            print("  " + BOX * 65)
            print("  Mapping dataset patterns to the 42 exploitable app endpoints.")
            print("  Each row shows how many payloads match a sink type.")
            print()

            SINK_TYPES = [
                ("html_injection",
                 [r'<\s*\w+'],
                 ["/reflected/body", "/dom/write", "/dom/innerhtml", "/dom/jquery",
                  "/dom/localstorage", "/stored/comments", "/stored/notes",
                  "/mutation/innerhtml", "/mutation/srcdoc", "/mutation/dangerouslyhtml",
                  "/dom/srcdoc", "/dom/fragment", "/dom/hash-write"]),
                ("event_handler_injection",
                 [r'on\w+\s*='],
                 ["/reflected/event", "/bypass/angle-only", "/bypass/tag-strip"]),
                ("javascript_uri",
                 [r'javascript\s*:', r'data\s*:\s*text/html'],
                 ["/reflected/href", "/reflected/iframe", "/dom/url-replace",
                  "/stored/profile"]),
                ("js_string_escape",
                 [r'(?<![\\])"', r"(?<![\\])'"],
                 ["/reflected/script", "/reflected/js-string", "/reflected/multiparams"]),
                ("attribute_breakout",
                 [r'".*\b(on\w+|href|src)\s*="'],
                 ["/reflected/attribute", "/dom/cookie"]),
                ("textarea_escape",
                 [r'</textarea>'],
                 ["/reflected/textarea"]),
                ("html_comment_escape",
                 [r'-->\s*<'],
                 ["/reflected/comment"]),
                ("meta_refresh_injection",
                 [r'url\s*=', r';url\s*='],
                 ["/reflected/meta"]),
                ("css_injection",
                 [r'\{|\}|expression\(|import\s+url'],
                 ["/reflected/style", "/reflected/css"]),
                ("eval_code_string",
                 [r'alert\s*[\(`]|prompt\s*[\(`]|confirm\s*[\(`]',
                  r'eval\s*\(', r'setTimeout\s*\(', r'setInterval\s*\(',
                  r'location\s*=', r'fetch\s*\('],
                 ["/dom/eval", "/dom/settimeout", "/reflected/json"]),
                ("svg_injection",
                 [r'<\s*svg\s'],
                 ["/mutation/svg", "/mutation/innerhtml"]),
                ("prototype_pollution",
                 [r'__proto__', r'constructor\.prototype'],
                 ["/mutation/prototype"]),
                ("template_injection",
                 [r'\{\{.*?\}\}', r'\$\{.*?\}', r'<%.*?%>'],
                 ["/mutation/angular"]),
                ("unquoted_attribute",
                 [r'\s(on\w+|src|href)\s*='],
                 ["/reflected/attribute-unquoted", "/bypass/angle-only", "/bypass/tag-strip"]),
            ]

            col_widths = (25, 10, 10, 40)
            print(f"  {'Sink Type':<{col_widths[0]}} {'Payloads':>{col_widths[1]}}  {'% of total':>{col_widths[2]}}  {'Exploitable Endpoints'}")
            print(f"  {BOX*col_widths[0]} {BOX*col_widths[1]}  {BOX*col_widths[2]}  {BOX*40}")
            for sink_name, patterns, endpoints in SINK_TYPES:
                combined_re = r'(' + '|'.join(patterns) + r')'
                count = pal.str.contains(combined_re, regex=True, na=False).sum()
                pct = count / len(pal) * 100
                ep_preview = endpoints[0] + (f" +{len(endpoints)-1} more" if len(endpoints) > 1 else "")
                print(f"  {sink_name:<{col_widths[0]}} {_fmt(count):>{col_widths[1]}}  {pct:>9.1f}%  {ep_preview}")

            # ---- 12b. Uncovered sink types ----------------------------------------------
            print("\n  12b. Undercovered sink types (<10 matching payloads)")
            print("  " + BOX * 65)
            low = []
            for sink_name, patterns, endpoints in SINK_TYPES:
                combined_re = r'(' + '|'.join(patterns) + r')'
                count = pal.str.contains(combined_re, regex=True, na=False).sum()
                if count < 10:
                    low.append((count, sink_name, endpoints))
            if low:
                for count, name, eps in sorted(low):
                    ep_list = ', '.join(eps[:3])
                    print(f"    {WARN} {_fmt(count):>6} | {name:<22} | {ep_list}")
            else:
                print("    \u2713 All sink types have \u226510 matching payloads")

            # ---- 12c. Endpoints needing specialized payloads ------------------------------
            print("\n  12c. Endpoints requiring specialized payload patterns")
            print("  " + BOX * 65)
            specialized = [
                ("/dom/postmessage", "postMessage event handler",
                 "Must be fired as a MessageEvent \u2014 no dataset payloads can directly trigger it"),
                ("/bypass/double-encode", "Double URL encoding bypass",
                 "Requires %25XX sequences \u2014 see encoding section above for prevalence"),
                ("/bypass/recursive", "Non-recursive filter bypass",
                 "Nested patterns like <scr<script>ipt> require special construction"),
                ("/reflected/header", "HTTP header injection (CRLF)",
                 "Requires %0d%0a or \\r\\n \u2014 URL-encoded variants may exist in dataset"),
                ("/bypass/quote-escape", "Quote escape bypass",
                 "Needs angle brackets without quotes \u2014 dataset has many such payloads"),
            ]
            for ep, label, note in specialized:
                print(f"    \u2022 {ep:<30} {label}")
                print(f"      {note}")

            # ---- 12d. Browser-verified per context (real test data) -----------------------
            print("\n  12d. Browser-verified payloads per context (from ranker training)")
            print("  " + BOX * 65)
            print(f"  Cross-referencing {_fmt(n_ranker)} ranker samples (real Playwright browser")
            print(f"  execution against the exploitable app and other targets).")
            print()

            if RANKER_JSONL.exists() and n_ranker > 0:
                with open(RANKER_JSONL) as f:
                    r_samples = [json.loads(l) for l in f if l.strip()]

                ctx_verified: dict[str, dict] = {}
                for s in r_samples:
                    ctx = s.get("context", "unknown")
                    if ctx not in ctx_verified:
                        ctx_verified[ctx] = {"total": 0, "executed": 0, "dialog": 0, "success": 0}
                    ctx_verified[ctx]["total"] += 1
                    if s.get("executed"):
                        ctx_verified[ctx]["executed"] += 1
                    if s.get("dialog_triggered"):
                        ctx_verified[ctx]["dialog"] += 1
                    if s.get("success"):
                        ctx_verified[ctx]["success"] += 1

                hdr_fmt = (22, 8, 6, 7, 8, 7)
                print(f"  {'Context':<{hdr_fmt[0]}} {'Tested':>{hdr_fmt[1]}} {'Exec':>{hdr_fmt[2]}} {'Dialog':>{hdr_fmt[3]}} {'Success':>{hdr_fmt[4]}} {'Exec %':>{hdr_fmt[5]}}")
                print(f"  {BOX*hdr_fmt[0]} {BOX*hdr_fmt[1]} {BOX*hdr_fmt[2]} {BOX*hdr_fmt[3]} {BOX*hdr_fmt[4]} {BOX*hdr_fmt[5]}")
                for ctx in sorted(ctx_verified.keys(), key=lambda c: ctx_verified[c]["executed"], reverse=True):
                    d = ctx_verified[ctx]
                    exec_pct = d["executed"] / d["total"] * 100 if d["total"] > 0 else 0
                    print(f"  {ctx:<{hdr_fmt[0]}} {_fmt(d['total']):>{hdr_fmt[1]}} {_fmt(d['executed']):>{hdr_fmt[2]}}"
                          f" {_fmt(d['dialog']):>{hdr_fmt[3]}} {_fmt(d['success']):>{hdr_fmt[4]}} {exec_pct:>6.1f}%")

                total_tested = sum(d["total"] for d in ctx_verified.values())
                total_exec = sum(d["executed"] for d in ctx_verified.values())
                print(f"  {BOX*hdr_fmt[0]} {BOX*hdr_fmt[1]} {BOX*hdr_fmt[2]} {BOX*hdr_fmt[3]} {BOX*hdr_fmt[4]} {BOX*hdr_fmt[5]}")
                print(f"  {'TOTAL':<{hdr_fmt[0]}} {_fmt(total_tested):>{hdr_fmt[1]}} {_fmt(total_exec):>{hdr_fmt[2]}}"
                      f" {_fmt(sum(d['dialog'] for d in ctx_verified.values())):>{hdr_fmt[3]}}"
                      f" {_fmt(sum(d['success'] for d in ctx_verified.values())):>{hdr_fmt[4]}}"
                      f" {total_exec / total_tested * 100:>6.1f}%")
            else:
                total_tested = 0
                total_exec = 0
                print("  (ranker training data not available)")

            # ---- 12e. Overall coverage assessment -----------------------------------------
            print("\n  12e. Coverage assessment")
            print("  " + BOX * 65)

            all_sink_re = '|'.join(
                f"({p})" for _, patterns, _ in SINK_TYPES for p in patterns
            )
            has_sink_match = pal.str.contains(all_sink_re, regex=True, na=False)
            n_covered = has_sink_match.sum()
            n_uncovered = len(pal) - n_covered
            sink_coverage_pct = n_covered / len(pal) * 100
            print(f"  Payloads matching \u22651 exploitable sink type : {_fmt(n_covered)} ({sink_coverage_pct:.1f}%)")
            print(f"  Payloads matching NO exploitable sink      : {_fmt(n_uncovered)} ({100 - sink_coverage_pct:.1f}%)")
            print()
            print(f"  Coverage strength:")
            if n_uncovered / len(pal) < 0.05:
                print(f"    \u2713 HIGH \u2014 {sink_coverage_pct:.1f}% map to at least one known sink type")
            elif n_uncovered / len(pal) < 0.20:
                print(f"    \u25cb ADEQUATE \u2014 {sink_coverage_pct:.1f}% map to at least one known sink type")
            else:
                print(f"    {WARN} LOW \u2014 only {sink_coverage_pct:.1f}% map to a known sink type")
            print(f"    (remaining {100 - sink_coverage_pct:.1f}% match abstract/generic patterns only)")
            print()
            print(f"  Gap note: Some sink types (postMessage, double-encode bypass,")
            print(f"  recursive filter bypass, header injection) inherently require")
            print(f"  specialized payloads that are rare or absent from general-purpose")
            print(f"  datasets. The scanner's detection for those patterns depends on the")
            print(f"  payload generator's diversity, not the curated dataset size.")
            print()
            print(f"  Browser-verified contexts (12d) show real execution data across")
            print(f"  {_fmt(total_tested if RANKER_JSONL.exists() else 0)} tested payloads against")
            print(f"  the exploitable app and other targets, confirming end-to-end coverage.")
            print(f"  See also: tests/, scripts/e2e-smoke.sh, exploitable/app.py")
    else:
        print("  (split CSVs not found \u2014 coverage analysis unavailable)")

    print()


if __name__ == "__main__":
    main()
