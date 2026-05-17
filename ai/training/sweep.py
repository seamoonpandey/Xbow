#!/usr/bin/env python3
"""
RedSentinel AI — Optuna Hyperparameter Sweep
=============================================

Automated hyperparameter optimization for the XSS classifier.
Runs multiple training trials with different hyperparameters sampled from
a defined search space, using Optuna's Bayesian optimization (TPESampler)
and MedianPruner to efficiently find the best configuration.

Usage:
    python sweep.py                           # New sweep (20 trials)
    python sweep.py --study <name>            # Continue existing study
    python sweep.py --n-trials 50             # Run more trials
    python sweep.py --list                    # List all studies
    python sweep.py --analyze <study_name>    # Show best params from a study
"""

import warnings
# Suppress noisy pyarrow deprecation warning (pandas 3.0 compat note)
# Must be done before any pandas import
warnings.simplefilter("ignore", DeprecationWarning)

import argparse
import json
import time
import math
import sys
from pathlib import Path
from collections import Counter

import optuna
from optuna.pruners import MedianPruner
from optuna.samplers import TPESampler
from optuna.trial import TrialState
import torch
import torch.nn as nn

import pandas as pd
from torch.optim import AdamW
from torch.amp import autocast, GradScaler

# Add ai/training to path for imports
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from config import (
    DEVICE, USE_AMP, BATCH_SIZE, MAX_GRAD_NORM,
    CONTEXT_CLASSES, SEVERITY_CLASSES,
    CONTEXT_LABELS, SEVERITY_LABELS,
    TRAIN_FILE, RUN_LOG_DIR, JOINT_HEAD,
    # Sweep-specific config
    SWEEP_N_TRIALS, SWEEP_EPOCHS, SWEEP_PATIENCE, SWEEP_STUDY_NAME,
    SWEEP_TIMEOUT_MINUTES,
    SWEEP_LR_MIN, SWEEP_LR_MAX,
    SWEEP_DROPOUT_MIN, SWEEP_DROPOUT_MAX,
    SWEEP_WARMUP_MIN, SWEEP_WARMUP_MAX,
    SWEEP_WEIGHT_DECAY_MIN, SWEEP_WEIGHT_DECAY_MAX,
    SWEEP_LABEL_SMOOTHING_MIN, SWEEP_LABEL_SMOOTHING_MAX,
    SWEEP_CTX_LOSS_WEIGHT_MIN, SWEEP_CTX_LOSS_WEIGHT_MAX,
)
from dataset import get_dataloaders

# Import shared training utilities from train.py
from train import train_one_epoch, validate, get_scheduler

# Need to import XSSClassifier directly for custom param passing
_MODEL_DIR = str(Path(__file__).resolve().parent.parent.parent / "model")
if _MODEL_DIR not in sys.path:
    sys.path.insert(0, _MODEL_DIR)
from xss_classifier import XSSClassifier


# ═══════════════════════════════════════════════════════════════════════
#  CACHED CLASS WEIGHTS & DATALOADERS
# ═══════════════════════════════════════════════════════════════════════

_CACHED_WEIGHTS = None
_CACHED_LOADERS = None


def _get_weights(device):
    """Return cached class-weight tensors (computed once)."""
    global _CACHED_WEIGHTS
    if _CACHED_WEIGHTS is not None:
        return _CACHED_WEIGHTS

    df = pd.read_csv(TRAIN_FILE)

    ctx_counts = Counter(df["context"].str.strip().str.lower())
    total_ctx = sum(ctx_counts.values())
    n_ctx = len(CONTEXT_LABELS)
    ctx_weight = torch.tensor([
        total_ctx / (n_ctx * ctx_counts.get(label, 1))
        for label in CONTEXT_LABELS
    ], dtype=torch.float, device=device)

    sev_counts = Counter(df["severity"].str.strip().str.lower())
    total_sev = sum(sev_counts.values())
    n_sev = len(SEVERITY_LABELS)
    sev_weight = torch.tensor([
        total_sev / (n_sev * sev_counts.get(label, 1))
        for label in SEVERITY_LABELS
    ], dtype=torch.float, device=device)

    _CACHED_WEIGHTS = (ctx_weight, sev_weight)
    return _CACHED_WEIGHTS


def _get_loaders():
    """Return cached DataLoaders (built once)."""
    global _CACHED_LOADERS
    if _CACHED_LOADERS is not None:
        return _CACHED_LOADERS
    _CACHED_LOADERS = get_dataloaders(BATCH_SIZE)
    return _CACHED_LOADERS


# ═══════════════════════════════════════════════════════════════════════
#  TRIAL TRAINING LOOP
# ═══════════════════════════════════════════════════════════════════════

def run_trial(params: dict, trial_dir: Path, trial=None) -> dict:
    """Train the model with the given hyperparameters for a full sweep trial.

    Reuses ``train_one_epoch`` and ``validate`` from ``train.py`` to avoid
    code duplication.  DataLoaders and class weights are built once and cached.

    Args:
        params:     Dict of hyperparameters (learning_rate, dropout, etc.).
        trial_dir:  Directory to save trial artifacts.
        trial:      Optuna trial object (for pruning/reporting).

    Returns:
        Dict with best_val_loss, best_val_context_acc, best_val_severity_acc,
        epochs_completed.
    """
    device = DEVICE

    # ── Unpack params with defaults ──
    lr              = params.get("learning_rate", 2e-5)
    dropout         = params.get("dropout", 0.3)
    freeze_layers   = params.get("freeze_layers", 0)
    warmup_ratio    = params.get("warmup_ratio", 0.1)
    weight_decay    = params.get("weight_decay", 0.01)
    label_smoothing = params.get("label_smoothing", 0.1)
    ctx_loss_weight = params.get("context_loss_weight", 0.7)
    sev_loss_weight = params.get("severity_loss_weight", 0.3)
    epochs          = params.get("epochs", SWEEP_EPOCHS)
    patience        = params.get("patience", SWEEP_PATIENCE)

    # ── Cached data ──
    train_loader, val_loader, _ = _get_loaders()
    ctx_weight, sev_weight = _get_weights(device)

    # ── Model ──
    model = XSSClassifier(
        num_contexts=CONTEXT_CLASSES,
        num_severities=SEVERITY_CLASSES,
        dropout=dropout,
        freeze_layers=freeze_layers,
        joint_head=JOINT_HEAD,
    ).to(device)

    # ── Loss criteria ──
    ctx_criterion = nn.CrossEntropyLoss(weight=ctx_weight, label_smoothing=label_smoothing)
    sev_criterion = nn.CrossEntropyLoss(weight=sev_weight, label_smoothing=label_smoothing)

    # ── Optimizer ──
    trainable = [p for p in model.parameters() if p.requires_grad]
    optimizer = AdamW(trainable, lr=lr, weight_decay=weight_decay, betas=(0.9, 0.999), eps=1e-8)

    # ── Scheduler ──
    total_steps = len(train_loader) * epochs
    warmup_steps = int(total_steps * warmup_ratio)
    scheduler = get_scheduler(optimizer, warmup_steps, total_steps)

    # ── Scaler ──
    scaler = GradScaler(device=DEVICE.type) if USE_AMP and DEVICE.type == "cuda" else None

    # ── Training loop ──
    # Build a minimal logger that suppresses per-batch logs for speed
    import logging
    trial_logger = logging.getLogger(f"trial_{trial.number if trial is not None else 'anon'}")
    trial_logger.setLevel(logging.WARNING)
    if not trial_logger.handlers:
        trial_logger.addHandler(logging.NullHandler())

    best_val_loss = float("inf")
    best_ctx_acc = 0.0
    best_sev_acc = 0.0
    patience_counter = 0
    epochs_completed = 0

    for epoch in range(epochs):
        train_metrics = train_one_epoch(
            model, train_loader, optimizer, scheduler, scaler,
            ctx_criterion, sev_criterion, epoch, trial_logger,
        )

        val_metrics = validate(
            model, val_loader, ctx_criterion, sev_criterion, trial_logger,
        )

        val_loss = val_metrics["val_loss"]
        ctx_acc = val_metrics["val_context_acc"]
        sev_acc = val_metrics["val_severity_acc"]

        # ── Report to Optuna for pruning ──
        if trial is not None:
            trial.report(val_loss, epoch)
            if trial.should_prune():
                del model, optimizer, scheduler, scaler
                if device.type == "cuda":
                    torch.cuda.empty_cache()
                raise optuna.TrialPruned()

        # ── Track best ──
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_ctx_acc = ctx_acc
            best_sev_acc = sev_acc
            patience_counter = 0
        else:
            patience_counter += 1

        epochs_completed = epoch + 1

        if patience_counter >= patience:
            break

    # ── Log trial params & results ──
    results = {
        "best_val_loss": round(best_val_loss, 6),
        "best_val_context_acc": round(best_ctx_acc, 2),
        "best_val_severity_acc": round(best_sev_acc, 2),
        "epochs_completed": epochs_completed,
        "total_epochs": epochs,
        "stopped_early": epochs_completed < epochs,
    }

    with open(trial_dir / "results.json", "w") as f:
        json.dump({**params, **results}, f, indent=2)

    # Cleanup GPU memory
    del model, optimizer, scheduler, scaler
    if device.type == "cuda":
        torch.cuda.empty_cache()

    return results


# ═══════════════════════════════════════════════════════════════════════
#  OPTUNA OBJECTIVE
# ═══════════════════════════════════════════════════════════════════════

def optuna_objective(trial):
    """Optuna objective: sample hyperparams, train, return best val loss.

    Uses trial.suggest_* calls so Optuna can track the search space
    and apply Bayesian optimization via TPESampler.
    """
    # ── Sample hyperparameters ──
    ctx_loss = trial.suggest_float("context_loss_weight", SWEEP_CTX_LOSS_WEIGHT_MIN, SWEEP_CTX_LOSS_WEIGHT_MAX)
    params = {
        "learning_rate": trial.suggest_float("learning_rate", SWEEP_LR_MIN, SWEEP_LR_MAX, log=True),
        "dropout": trial.suggest_float("dropout", SWEEP_DROPOUT_MIN, SWEEP_DROPOUT_MAX),
        "freeze_layers": trial.suggest_int("freeze_layers", 0, 2),
        "warmup_ratio": trial.suggest_float("warmup_ratio", SWEEP_WARMUP_MIN, SWEEP_WARMUP_MAX),
        "weight_decay": trial.suggest_float("weight_decay", SWEEP_WEIGHT_DECAY_MIN, SWEEP_WEIGHT_DECAY_MAX, log=True),
        "label_smoothing": trial.suggest_float("label_smoothing", SWEEP_LABEL_SMOOTHING_MIN, SWEEP_LABEL_SMOOTHING_MAX),
        "context_loss_weight": ctx_loss,
        "severity_loss_weight": 1.0 - ctx_loss,
    }

    # ── Trial directory for artifacts ──
    trial_dir = RUN_LOG_DIR / "sweeps" / f"trial_{trial.number:03d}"
    trial_dir.mkdir(parents=True, exist_ok=True)

    # Save sampled params
    with open(trial_dir / "params.json", "w") as f:
        json.dump(params, f, indent=2)

    # ── Train ──
    result = run_trial(params, trial_dir, trial=trial)

    # Log intermediate values for Optuna's visualization
    trial.set_user_attr("context_acc", result["best_val_context_acc"])
    trial.set_user_attr("severity_acc", result["best_val_severity_acc"])
    trial.set_user_attr("epochs_completed", result["epochs_completed"])

    return result["best_val_loss"]


# ═══════════════════════════════════════════════════════════════════════
#  SWEEP ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

def run_sweep(study_name: str = SWEEP_STUDY_NAME, n_trials: int = SWEEP_N_TRIALS):
    """Create or resume an Optuna study and run the specified number of trials.

    Study is persisted via SQLite in the runs/ directory, so interrupted
    sweeps can be resumed with ``--study <name>``.

    Args:
        study_name: Name of the study (used for the SQLite DB filename).
        n_trials:   Number of trials to run in this session.
    """
    storage_path = str(RUN_LOG_DIR / f"{study_name}.db")
    study_dir = RUN_LOG_DIR / study_name
    study_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"  🔬 Optuna Hyperparameter Sweep")
    print(f"{'=' * 60}")
    print(f"  Study name:  {study_name}")
    print(f"  Storage:     {storage_path}")
    print(f"  Trials:      {n_trials}")
    print(f"  Epochs/trial: {SWEEP_EPOCHS} (patience={SWEEP_PATIENCE})")
    print(f"  Device:      {DEVICE}")
    print(f"  Timeout:     {SWEEP_TIMEOUT_MINUTES}m")

    # Warm up cache (build loaders + weights once before trials start)
    print(f"\n  🔄 Pre-caching DataLoaders and class weights...")
    _get_loaders()
    _get_weights(DEVICE)
    print(f"  ✓ Data ready")

    # Create or load study
    sampler = TPESampler(seed=42, n_startup_trials=5)
    pruner = MedianPruner(
        n_startup_trials=5,
        n_warmup_steps=2,
        interval_steps=1,
    )

    study = optuna.create_study(
        study_name=study_name,
        storage=f"sqlite:///{storage_path}",
        sampler=sampler,
        pruner=pruner,
        direction="minimize",
        load_if_exists=True,
    )

    print(f"\n  Existing trials: {len(study.trials)}")
    completed = len([t for t in study.trials if t.state == TrialState.COMPLETE])
    pruned = len([t for t in study.trials if t.state == TrialState.PRUNED])
    running = len([t for t in study.trials if t.state == TrialState.RUNNING])
    print(f"    Complete: {completed}")
    print(f"    Pruned:   {pruned}")
    print(f"    Running:  {running}")

    # ── Run optimization ──
    timeout_seconds = SWEEP_TIMEOUT_MINUTES * 60

    print(f"\n{'─' * 60}")
    print(f"  🚀 Starting optimization ({n_trials} new trials)...")
    print(f"{'─' * 60}\n")

    start_time = time.time()

    # Check if tqdm is available for progress bar
    try:
        import tqdm  # noqa: F401
        show_progress = True
    except ImportError:
        show_progress = False
        print("  (install tqdm for progress bar: pip install tqdm)")

    study.optimize(
        optuna_objective,
        n_trials=n_trials,
        timeout=timeout_seconds,
        show_progress_bar=show_progress,
    )

    elapsed = time.time() - start_time

    # ── Results ──
    print(f"\n{'=' * 60}")
    print(f"  ✅ Sweep Complete!")
    print(f"{'=' * 60}")
    print(f"  Time elapsed:    {elapsed / 60:.1f} minutes")

    best_trial = study.best_trial
    print(f"\n  🏆 Best Trial (#{best_trial.number}):")
    print(f"  ┌──────────────────────┬────────────────────┐")
    for key, value in best_trial.params.items():
        print(f"  │ {key:<20} │ {str(value):>18} │")
    print(f"  ├──────────────────────┼────────────────────┤")
    print(f"  │ {'val_loss':<20} │ {best_trial.value:>18.6f} │")
    for key in ["context_acc", "severity_acc"]:
        if key in best_trial.user_attrs:
            print(f"  │ {key:<20} │ {best_trial.user_attrs[key]:>18.2f} │")
    print(f"  └──────────────────────┴────────────────────┘")

    # ── Save best params ──
    best_params = {
        "trial_number": best_trial.number,
        "val_loss": best_trial.value,
        "params": best_trial.params,
        "user_attrs": dict(best_trial.user_attrs),
    }
    with open(study_dir / "best_params.json", "w") as f:
        json.dump(best_params, f, indent=2)

    print(f"\n  💾 Best params saved → {study_dir / 'best_params.json'}")
    print(f"  📊 View with:   optuna-dashboard sqlite:///{storage_path}")
    print(f"  📋 Analyze with: python sweep.py --analyze {study_name}")

    # ── Summary table ──
    print(f"\n  Trial Summary (top 5):")
    print(f"  ┌───────┬────────────┬──────────┬──────────┬──────────┬─────────┐")
    print(f"  │ Trial │ Val Loss   │ Ctx Acc  │ Sev Acc  │ Epochs   │ State   │")
    print(f"  ├───────┼────────────┼──────────┼──────────┼──────────┼─────────┤")

    sorted_trials = sorted(
        [t for t in study.trials if t.state == TrialState.COMPLETE],
        key=lambda t: t.value if t.value is not None else float("inf"),
    )

    for t in sorted_trials[:5]:
        ca = t.user_attrs.get("context_acc", 0)
        sa = t.user_attrs.get("severity_acc", 0)
        ec = t.user_attrs.get("epochs_completed", SWEEP_EPOCHS)
        state = "COMPLETE" if t.state == TrialState.COMPLETE else str(t.state.name)
        marker = " ◀ BEST" if t.number == best_trial.number else ""
        print(f"  │  {t.number:>3}  │  {t.value:>8.6f}  │ {ca:>6.1f}% │ {sa:>6.1f}% │  {ec:>3}/{SWEEP_EPOCHS}  │ {state:8s}{marker} │")

    print(f"  └───────┴────────────┴──────────┴──────────┴──────────┴─────────┘")

    pruned_count = len([t for t in study.trials if t.state == TrialState.PRUNED])
    if pruned_count > 0:
        print(f"\n  ⚡ {pruned_count} trials were pruned (MedianPruner stopped poor performers early)")

    return study


# ═══════════════════════════════════════════════════════════════════════
#  ANALYSIS UTILITIES
# ═══════════════════════════════════════════════════════════════════════

def list_studies():
    """List all completed sweep studies in the runs/ directory."""
    studies = sorted(RUN_LOG_DIR.glob("*_sweep.db"))
    if not studies:
        print(f"  No studies found in {RUN_LOG_DIR}")
        return

    print(f"\n  Available studies in {RUN_LOG_DIR}:")
    for s in studies:
        size_kb = s.stat().st_size / 1024
        name = s.stem
        print(f"    {name:<35s} ({size_kb:.1f} KB)")


def analyze_study(study_name: str):
    """Print detailed results for a completed sweep study."""
    storage_path = str(RUN_LOG_DIR / f"{study_name}.db")
    if not Path(storage_path).exists():
        print(f"  ❌ Study not found: {storage_path}")
        print(f"  Run with --list to see available studies")
        return

    study = optuna.load_study(
        study_name=study_name,
        storage=f"sqlite:///{storage_path}",
    )

    print(f"\n{'=' * 60}")
    print(f"  📊 Sweep Analysis: {study_name}")
    print(f"{'=' * 60}")

    completed = [t for t in study.trials if t.state == TrialState.COMPLETE]
    pruned = [t for t in study.trials if t.state == TrialState.PRUNED]

    print(f"\n  Summary:")
    print(f"    Total trials:  {len(study.trials)}")
    print(f"    Complete:      {len(completed)}")
    print(f"    Pruned:        {len(pruned)}")
    if completed:
        values = [t.value for t in completed if t.value is not None]
        print(f"    Best val loss: {min(values):.6f}")
        print(f"    Mean val loss: {sum(values)/len(values):.6f}")

    if study.best_trial:
        print(f"\n  🏆 Best Trial (#{study.best_trial.number}):")
        print(f"  ┌──────────────────────┬────────────────────┐")
        for key, value in study.best_trial.params.items():
            print(f"  │ {key:<20} │ {str(value):>18} │")
        print(f"  ├──────────────────────┼────────────────────┤")
        print(f"  │ {'val_loss':<20} │ {study.best_trial.value:>18.6f} │")
        for key in ["context_acc", "severity_acc"]:
            if key in study.best_trial.user_attrs:
                print(f"  │ {key:<20} │ {study.best_trial.user_attrs[key]:>18.2f} │")
        print(f"  └──────────────────────┴────────────────────┘")

    if completed:
        print(f"\n  All Completed Trials (sorted by val loss):")
        print(f"  ┌───────┬────────────┬──────────┬──────────┬──────────┐")
        print(f"  │ Trial │ Val Loss   │ Ctx Acc  │ Sev Acc  │ Epochs   │")
        print(f"  ├───────┼────────────┼──────────┼──────────┼──────────┤")
        sorted_trials = sorted(completed, key=lambda t: t.value if t.value is not None else float("inf"))
        for t in sorted_trials:
            ca = t.user_attrs.get("context_acc", 0)
            sa = t.user_attrs.get("severity_acc", 0)
            ec = t.user_attrs.get("epochs_completed", SWEEP_EPOCHS)
            marker = " ◀" if t.number == study.best_trial.number else ""
            print(f"  │  {t.number:>3}  │  {t.value:>8.6f}  │ {ca:>6.1f}% │ {sa:>6.1f}% │  {ec:>3}/{SWEEP_EPOCHS}  │{marker}")
        print(f"  └───────┴────────────┴──────────┴──────────┴──────────┘")

    # Hyperparameter importance
    if len(completed) >= 5:
        try:
            importance = optuna.importance.get_param_importances(study)
            print(f"\n  🔍 Hyperparameter Importance:")
            print(f"  ┌──────────────────────┬──────────┐")
            for param, imp in sorted(importance.items(), key=lambda x: -x[1]):
                bar = "█" * int(imp * 50)
                print(f"  │ {param:<20} │  {imp:.3f}  {bar}")
            print(f"  └──────────────────────┴──────────┘")
        except Exception as e:
            print(f"\n  (Could not compute param importance: {e})")


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="RedSentinel AI — Optuna Hyperparameter Sweep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python sweep.py                        # New sweep (20 trials)
  python sweep.py --n-trials 50           # Run 50 trials
  python sweep.py --study study_name      # Resume/name a study
  python sweep.py --list                  # List all studies
  python sweep.py --analyze study_name    # Analyze a completed study
        """,
    )
    parser.add_argument("--study", type=str, default=SWEEP_STUDY_NAME,
                        help=f"Study name (default: {SWEEP_STUDY_NAME})")
    parser.add_argument("--n-trials", "--n_trials", type=int, default=SWEEP_N_TRIALS,
                        help=f"Number of trials (default: {SWEEP_N_TRIALS})")
    parser.add_argument("--list", action="store_true",
                        help="List all completed studies")
    parser.add_argument("--analyze", type=str, nargs="?", const="__latest__",
                        help="Analyze a completed study (default: latest)")
    args = parser.parse_args()

    if args.list:
        list_studies()
        return

    if args.analyze:
        if args.analyze == "__latest__":
            studies = sorted(RUN_LOG_DIR.glob("*_sweep.db"),
                             key=lambda p: p.stat().st_mtime, reverse=True)
            if not studies:
                print("  No studies found.")
                return
            args.analyze = studies[0].stem
        analyze_study(args.analyze)
        return

    run_sweep(study_name=args.study, n_trials=args.n_trials)


if __name__ == "__main__":
    main()
