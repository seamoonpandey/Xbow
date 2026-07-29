#!/usr/bin/env python3
"""
audit_labels — dataset honesty checks for the context/severity classifier.

Answers three questions the accuracy number hides:

  1. LEAKAGE   — do test payloads appear in training? (memorization, not generalization)
  2. TRIVIALITY — can a rule reproduce the labels? If yes, a learned model over them
                  measures how well it imitates the rule, not anything about the data.
  3. MISMATCH  — is the model trained on the same kind of string it sees at inference?

Exits nonzero if leakage or triviality cross the thresholds, so it works as a CI gate.
This does NOT fix the labels — it proves whether they need fixing. Real labels have to
describe how a payload REFLECTED or whether it EXECUTED, which the payload string alone
cannot tell you; that grounding comes from real scan outcomes, not this script.

Usage:
    python scripts/audit_labels.py                 # uses dataset/splits/{train,val,test}.csv
    python scripts/audit_labels.py --dir some/dir  # CSVs with a `payload` column
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

# Reuse the ACTUAL labeling rules — no reimplementation, single source of truth.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dataset"))
from label_contexts import classify_context, get_severity  # noqa: E402

# A learned model is only worth its cost if it beats the rule by a real margin.
# Above these, the labels are a rule in disguise and the leakage is memorization.
LEAKAGE_MAX = 0.05       # >5% test payloads seen in training = fail
TRIVIALITY_MAX = 0.90    # >90% of labels reproducible by rule = fail

# Where the model actually gets its input at inference, vs what it trains on.
# See modules/context-module/app.py: classifier.classify(context_snippet).
TRAIN_INPUT = "payload string"
INFER_INPUT = "reflected context_snippet (server response HTML around the payload)"


def load(split_dir: Path, name: str) -> pd.DataFrame:
    path = split_dir / f"{name}.csv"
    if not path.exists():
        sys.exit(f"missing split: {path}")
    df = pd.read_csv(path)
    if "payload" not in df.columns:
        sys.exit(f"{path} has no `payload` column (got {list(df.columns)})")
    return df


def leakage(train: pd.DataFrame, test: pd.DataFrame) -> tuple[float, int, int]:
    tr = set(train["payload"].astype(str))
    te = set(test["payload"].astype(str))
    both = tr & te
    frac = len(both) / len(te) if te else 0.0
    return frac, len(both), len(te)


def triviality(df: pd.DataFrame, col: str, rule) -> float:
    """Fraction of stored labels a rule reproduces exactly from the payload."""
    if col not in df.columns:
        return float("nan")
    stored = df[col].astype(str).str.strip().str.lower()
    derived = df["payload"].apply(rule).astype(str).str.strip().str.lower()
    return float((stored == derived).mean())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(Path(__file__).resolve().parent.parent
                                         / "dataset" / "splits"))
    args = ap.parse_args()
    d = Path(args.dir)

    train, test = load(d, "train"), load(d, "test")
    failed = []

    print("=" * 64)
    print("LABEL AUDIT")
    print("=" * 64)

    frac, n_both, n_test = leakage(train, test)
    verdict = "FAIL" if frac > LEAKAGE_MAX else "ok"
    if frac > LEAKAGE_MAX:
        failed.append(f"leakage {frac:.1%} > {LEAKAGE_MAX:.0%}")
    print(f"\n[1] LEAKAGE")
    print(f"    test payloads also in train: {n_both}/{n_test} = {frac:.2%}  [{verdict}]")

    print(f"\n[2] LABEL TRIVIALITY (rule reproduces the stored label)")
    for col, rule in (("context", classify_context), ("severity", get_severity)):
        t = triviality(test, col, rule)
        if t != t:  # NaN
            print(f"    {col:9s}: column absent")
            continue
        verdict = "FAIL" if t > TRIVIALITY_MAX else "ok"
        if t > TRIVIALITY_MAX:
            failed.append(f"{col} {t:.1%} rule-reproducible > {TRIVIALITY_MAX:.0%}")
        print(f"    {col:9s}: {t:.2%} reproducible by rule  [{verdict}]")

    print(f"\n[3] TRAIN/INFER INPUT MISMATCH")
    print(f"    trains on : {TRAIN_INPUT}")
    print(f"    infers on : {INFER_INPUT}")
    print(f"    -> label is computed from the payload, but the model is deployed on the")
    print(f"       reflection. Even a perfect score here does not measure the real task.")

    print("\n" + "=" * 64)
    if failed:
        print("VERDICT: labels are not trustworthy targets —")
        for f in failed:
            print(f"  - {f}")
        print("Fix requires reflection-/execution-grounded labels, not a rule over the payload.")
        return 1
    print("VERDICT: labels pass the honesty checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
