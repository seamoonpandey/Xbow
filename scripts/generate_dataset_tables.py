#!/usr/bin/env python3
"""Generate dataset evaluation tables (Table 6.1 and Table 6.2).

Writes output to `docs/evaluation/6.3_dataset_evaluation.md`.
"""
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SPLITS_DIR = ROOT / "dataset" / "splits"
OUT_MD = ROOT / "docs" / "evaluation" / "6.3_dataset_evaluation.md"


def load_splits():
    parts = {}
    for name in ["train", "val", "test"]:
        p = SPLITS_DIR / f"{name}.csv"
        if p.exists():
            df = pd.read_csv(p)
            df["_split"] = name
            parts[name] = df
    return parts


def fmt_count_pct(count, total):
    pct = 100.0 * count / total if total > 0 else 0.0
    return f"{int(count)} ({pct:.1f}%)"


def table_context_distribution(dfs):
    # contexts x splits
    all_df = pd.concat(dfs.values(), ignore_index=True)
    total = len(all_df)
    contexts = sorted(all_df["context"].dropna().unique())

    rows = []
    for ctx in contexts:
        train_c = len(dfs.get("train", pd.DataFrame())[dfs.get("train").context == ctx]) if "train" in dfs else 0
        val_c = len(dfs.get("val", pd.DataFrame())[dfs.get("val").context == ctx]) if "val" in dfs else 0
        test_c = len(dfs.get("test", pd.DataFrame())[dfs.get("test").context == ctx]) if "test" in dfs else 0
        tot = train_c + val_c + test_c
        rows.append((ctx, fmt_count_pct(train_c, tot) if tot>0 else "0 (0.0%)", fmt_count_pct(val_c, tot) if tot>0 else "0 (0.0%)", fmt_count_pct(test_c, tot) if tot>0 else "0 (0.0%)", str(tot)))

    md = []
    md.append("**6.3 Dataset Evaluation**")
    md.append("")
    md.append("**Table 6.1: Context Classification Dataset Distribution**")
    md.append("")
    md.append("- Note: counts shown as `count (percentage of context total)` per split.")
    md.append("")
    md.append("| Context | Train | Val | Test | Total |")
    md.append("|---|---:|---:|---:|---:|")
    for ctx, tr, va, te, tot in rows:
        md.append(f"| {ctx} | {tr} | {va} | {te} | {tot} |")
    md.append("")
    return "\n".join(md)


def table_payload_distribution(dfs):
    all_df = pd.concat(dfs.values(), ignore_index=True)
    total = len(all_df)
    unique = all_df["payload"].nunique()

    md = []
    md.append("**Table 6.2: Payload Dataset Distribution**")
    md.append("")
    md.append(f"- Total payloads: **{total}**; Unique payload texts: **{unique}**")
    md.append("")

    # by source (if present)
    if "source" in all_df.columns:
        src_counts = all_df["source"].value_counts()
        md.append("**By source**")
        md.append("")
        md.append("| Source | Count | Percentage |")
        md.append("|---|---:|---:|")
        for s, c in src_counts.items():
            md.append(f"| {s} | {c} | {100.0*c/total:.1f}% |")
        md.append("")

    # by technique
    if "technique" in all_df.columns:
        tech_counts = all_df["technique"].fillna("none").value_counts()
        md.append("**By technique**")
        md.append("")
        md.append("| Technique | Count | Percentage |")
        md.append("|---|---:|---:|")
        for t, c in tech_counts.items():
            md.append(f"| {t} | {c} | {100.0*c/total:.1f}% |")
        md.append("")

    # severity distribution
    if "severity" in all_df.columns:
        sev_counts = all_df["severity"].fillna("unknown").value_counts()
        md.append("**By severity**")
        md.append("")
        md.append("| Severity | Count | Percentage |")
        md.append("|---|---:|---:|")
        for s, c in sev_counts.items():
            md.append(f"| {s} | {c} | {100.0*c/total:.1f}% |")
        md.append("")

    return "\n".join(md)


def main():
    parts = load_splits()
    if not parts:
        print("No split CSVs found in dataset/splits. Exiting.")
        return

    md_parts = []
    md_parts.append(table_context_distribution(parts))
    md_parts.append(table_payload_distribution(parts))

    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n\n".join(md_parts))
    print(f"Wrote dataset evaluation to {OUT_MD}")


if __name__ == "__main__":
    main()
