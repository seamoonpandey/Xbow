# ai/training/train.py
"""
RedSentinel AI — Training Loop
Dual-head XSS classifier training with validation, checkpointing, early stopping.

This training pipeline is designed to work across three device backends:
  - CUDA  (NVIDIA GPU)  — full AMP (mixed precision) + GradScaler
  - MPS   (Apple Silicon) — AMP autocast supported, no GradScaler needed
  - CPU   (fallback)    — full float32, no AMP

The module detects your hardware automatically via config.py and adapts
all code paths (autocast, gradient scaling, data loading) accordingly.

Usage:
    python train.py
    python train.py --epochs 20 --lr 3e-5 --batch_size 64
    python train.py --resume
"""

import os
# ── MPS Compatibility ────────────────────────────────────
# On Apple Silicon, some PyTorch ops (e.g. gather, index_add in
# certain attention implementations) lack native MPS kernels.
# This env var forces a graceful CPU fallback for those ops.
# Has no effect on CUDA or CPU.
os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "1"

import argparse
import json
import csv
import time
import math
import logging
from pathlib import Path
from datetime import datetime
from collections import Counter

import torch
import torch.nn as nn
import pandas as pd
from torch.optim import AdamW
from torch.optim.lr_scheduler import LambdaLR
from torch.amp import autocast, GradScaler

from config import (
    DEVICE, USE_AMP, EPOCHS, BATCH_SIZE, LEARNING_RATE, WEIGHT_DECAY,
    WARMUP_RATIO, MAX_GRAD_NORM, PATIENCE,
    CONTEXT_LOSS_WEIGHT, SEVERITY_LOSS_WEIGHT, LABEL_SMOOTHING,
    CONTEXT_CLASSES, SEVERITY_CLASSES,
    CONTEXT_LABELS, SEVERITY_LABELS,
    CHECKPOINT_DIR, LOG_EVERY_N_STEPS, SAVE_EVERY_N_EPOCHS,
    TRAIN_FILE, RUN_LOG_DIR, FREEZE_LAYERS, JOINT_HEAD, DROPOUT,
    LR_FIND_MIN, LR_FIND_MAX, LR_FIND_STEP_MULTIPLIER,
)
from dataset import get_dataloaders
from model import build_model


# ═════════════════════════════════════════════════════════════
#                        UTILITIES
# ═════════════════════════════════════════════════════════════

def setup_logging() -> logging.Logger:
    """Configure dual logging: file + stdout."""
    log_dir = CHECKPOINT_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"train_{timestamp}.log"

    logger = logging.getLogger("redsentinel")
    logger.setLevel(logging.INFO)

    # Clear any existing handlers (prevents duplicate logs on re-runs)
    logger.handlers.clear()

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%H:%M:%S"))

    # Stdout handler
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(fh)
    logger.addHandler(sh)

    logger.info(f"📝 Logging to {log_file}")
    return logger


def get_scheduler(optimizer, num_warmup_steps: int, num_training_steps: int) -> LambdaLR:
    """Linear warmup → cosine decay."""

    def lr_lambda(current_step: int) -> float:
        if current_step < num_warmup_steps:
            return float(current_step) / float(max(1, num_warmup_steps))
        progress = float(current_step - num_warmup_steps) / float(
            max(1, num_training_steps - num_warmup_steps)
        )
        return max(0.0, 0.5 * (1.0 + math.cos(math.pi * progress)))

    return LambdaLR(optimizer, lr_lambda)


class MetricsTracker:
    """Track all training metrics across epochs."""

    def __init__(self):
        self.history = {
            "train_loss": [],
            "val_loss": [],
            "train_context_acc": [],
            "train_severity_acc": [],
            "val_context_acc": [],
            "val_severity_acc": [],
            "learning_rate": [],
            "epoch_time": [],
        }

    def record(self, metrics: dict):
        for key, value in metrics.items():
            if key in self.history:
                self.history[key].append(value)

    def save(self, path: Path):
        with open(path, "w") as f:
            json.dump(self.history, f, indent=2)

    def best_val_loss(self) -> float:
        if not self.history["val_loss"]:
            return float("inf")
        return min(self.history["val_loss"])


class RunLogger:
    """Logs experiment runs to timestamped directories for comparison."""

    def __init__(self, config_overrides: dict | None = None):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_dir = RUN_LOG_DIR / f"run_{timestamp}"
        self.run_dir.mkdir(parents=True, exist_ok=True)

        # Save config snapshot
        config_snapshot = {
            "timestamp": timestamp,
            "dataset": str(TRAIN_FILE),
            "batch_size": BATCH_SIZE,
            "learning_rate": LEARNING_RATE,
            "epochs": EPOCHS,
            "freeze_layers": FREEZE_LAYERS,
            "joint_head": JOINT_HEAD,
            "label_smoothing": LABEL_SMOOTHING,
            "context_loss_weight": CONTEXT_LOSS_WEIGHT,
            "severity_loss_weight": SEVERITY_LOSS_WEIGHT,
            "warmup_ratio": WARMUP_RATIO,
            "dropout": DROPOUT,
        }
        if config_overrides:
            config_snapshot.update(config_overrides)

        with open(self.run_dir / "config.json", "w") as f:
            json.dump(config_snapshot, f, indent=2)

        # Init metrics CSV
        self.metrics_path = self.run_dir / "metrics.csv"
        with open(self.metrics_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "epoch", "train_loss", "val_loss",
                "train_context_acc", "train_severity_acc",
                "val_context_acc", "val_severity_acc",
                "learning_rate", "epoch_time_seconds",
            ])

    def log_epoch(self, epoch: int, metrics: dict):
        with open(self.metrics_path, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                epoch + 1,
                f"{metrics.get('train_loss', 0):.4f}",
                f"{metrics.get('val_loss', 0):.4f}",
                f"{metrics.get('train_context_acc', 0):.1f}",
                f"{metrics.get('train_severity_acc', 0):.1f}",
                f"{metrics.get('val_context_acc', 0):.1f}",
                f"{metrics.get('val_severity_acc', 0):.1f}",
                f"{metrics.get('learning_rate', 0):.2e}",
                f"{metrics.get('epoch_time', 0):.1f}",
            ])

    @property
    def path(self) -> Path:
        return self.run_dir


# ═════════════════════════════════════════════════════════════
#                     CHECKPOINTING
# ═════════════════════════════════════════════════════════════

def save_checkpoint(model, optimizer, scheduler, scaler, epoch, val_loss, path):
    """Save full training state to disk.

    Args:
        model:        The PyTorch model (state_dict saved).
        optimizer:    AdamW optimizer state.
        scheduler:    LR scheduler state for resumability.
        scaler:       GradScaler (CUDA) or None (MPS/CPU).
                      Only saved if not None to avoid serialization errors.
        epoch:        Current epoch number.
        val_loss:     Validation loss at this epoch (for best-model tracking).
        path:         File path to save the checkpoint to.

    Note:
        On MPS, ``scaler`` is None because MPS doesn't use GradScaler.
    """
    ckpt = {
        "epoch": epoch,
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": optimizer.state_dict(),
        "scheduler_state_dict": scheduler.state_dict(),
        "val_loss": val_loss,
    }
    if scaler is not None:
        ckpt["scaler_state_dict"] = scaler.state_dict()
    torch.save(ckpt, path)


def load_checkpoint(path, model, optimizer, scheduler, scaler):
    """Restore training state from a checkpoint file.

    Args:
        path:      File path of the checkpoint (e.g. "latest.pt").
        model:     Model whose state_dict will be overwritten.
        optimizer: Optimizer to restore (LR, momentum buffers, etc.).
        scheduler: LR scheduler to restore step count from.
        scaler:    GradScaler (CUDA) or None (MPS/CPU).  Loaded
                   only if present in the checkpoint.

    Returns:
        Tuple of (epoch, val_loss) — the epoch & validation loss
        at which the checkpoint was saved.
    """
    ckpt = torch.load(path, map_location=DEVICE, weights_only=False)
    missing, unexpected = model.load_state_dict(ckpt["model_state_dict"], strict=False)
    if missing or unexpected:
        print(f"  ⚠  Checkpoint architecture mismatch — {len(missing)} missing, {len(unexpected)} unexpected keys")
        print(f"      (expected if architecture changed, e.g. joint_head toggle)")
    optimizer.load_state_dict(ckpt["optimizer_state_dict"])
    scheduler.load_state_dict(ckpt["scheduler_state_dict"])
    if scaler is not None and "scaler_state_dict" in ckpt:
        scaler.load_state_dict(ckpt["scaler_state_dict"])
    return ckpt["epoch"], ckpt["val_loss"]


# ═════════════════════════════════════════════════════════════
#                    TRAIN ONE EPOCH
# ═════════════════════════════════════════════════════════════

def train_one_epoch(
    model, loader, optimizer, scheduler, scaler,
    context_criterion, severity_criterion,
    epoch, logger
) -> dict:
    """Train the model for one full pass over the training data.

    Device-aware implementation:
      - CUDA: Uses ``autocast('cuda')`` + ``GradScaler`` for mixed precision.
      - MPS:  Uses ``autocast('mps')`` for mixed precision but NO GradScaler
              (MPS handles gradient scaling internally).
      - CPU:  Runs full float32 without AMP.

    Returns a dictionary with 'train_loss', 'train_context_acc',
    'train_severity_acc', 'epoch_time', and 'learning_rate'.
    """

    model.train()

    total_loss = 0.0
    ctx_correct = 0
    sev_correct = 0
    total_samples = 0
    num_batches = len(loader)

    epoch_start = time.time()

    for step, batch in enumerate(loader):
        # Move to device
        input_ids = batch["input_ids"].to(DEVICE)
        attention_mask = batch["attention_mask"].to(DEVICE)
        ctx_labels = batch["context_label"].to(DEVICE)
        sev_labels = batch["severity_label"].to(DEVICE)

        optimizer.zero_grad()

        # ── Forward (model returns tuple: ctx_logits, sev_logits) ──
        # ``autocast`` enables mixed precision for the forward pass.
        # On CUDA: float16 where safe, float32 where needed.
        # On MPS:  float16, no scaler needed (MPS handles it).
        # On CPU:  disabled entirely.
        with autocast(device_type=DEVICE.type, enabled=USE_AMP):
            ctx_logits, sev_logits = model(input_ids, attention_mask)

            # Dual weighted loss (context 70%, severity 30%)
            ctx_loss = context_criterion(ctx_logits, ctx_labels)
            sev_loss = severity_criterion(sev_logits, sev_labels)
            loss = (CONTEXT_LOSS_WEIGHT * ctx_loss) + (SEVERITY_LOSS_WEIGHT * sev_loss)

        # ── Backward ──
        # ``scaler`` exists only on CUDA.  On MPS we skip the scaler
        # entirely; on CPU we also skip it (AMP is disabled anyway).
        if scaler is not None:
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            nn.utils.clip_grad_norm_(model.parameters(), MAX_GRAD_NORM)
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), MAX_GRAD_NORM)
            optimizer.step()

        scheduler.step()

        # Track metrics
        bs = input_ids.size(0)
        total_loss += loss.item() * bs
        total_samples += bs
        ctx_correct += (ctx_logits.argmax(dim=-1) == ctx_labels).sum().item()
        sev_correct += (sev_logits.argmax(dim=-1) == sev_labels).sum().item()

        # Log every N steps
        if (step + 1) % LOG_EVERY_N_STEPS == 0:
            avg_loss = total_loss / total_samples
            ca = ctx_correct / total_samples * 100
            sa = sev_correct / total_samples * 100
            lr = scheduler.get_last_lr()[0]

            logger.info(
                f"  Step [{step+1:>4}/{num_batches}] — "
                f"Loss: {avg_loss:.4f} | "
                f"Ctx: {ca:.1f}% | "
                f"Sev: {sa:.1f}% | "
                f"LR: {lr:.2e}"
            )

    epoch_time = time.time() - epoch_start

    return {
        "train_loss": total_loss / total_samples,
        "train_context_acc": ctx_correct / total_samples * 100,
        "train_severity_acc": sev_correct / total_samples * 100,
        "epoch_time": epoch_time,
        "learning_rate": scheduler.get_last_lr()[0],
    }


# ═════════════════════════════════════════════════════════════
#                      VALIDATION
# ═════════════════════════════════════════════════════════════

@torch.no_grad()
def validate(model, loader, context_criterion, severity_criterion, logger) -> dict:
    """Run validation with per-class breakdown."""

    model.eval()

    total_loss = 0.0
    ctx_correct = 0
    sev_correct = 0
    total_samples = 0

    # Per-class tracking
    class_correct = [0] * CONTEXT_CLASSES
    class_total = [0] * CONTEXT_CLASSES

    for batch in loader:
        input_ids = batch["input_ids"].to(DEVICE)
        attention_mask = batch["attention_mask"].to(DEVICE)
        ctx_labels = batch["context_label"].to(DEVICE)
        sev_labels = batch["severity_label"].to(DEVICE)

        with autocast(device_type=DEVICE.type, enabled=USE_AMP):
            ctx_logits, sev_logits = model(input_ids, attention_mask)

            ctx_loss = context_criterion(ctx_logits, ctx_labels)
            sev_loss = severity_criterion(sev_logits, sev_labels)
            loss = (CONTEXT_LOSS_WEIGHT * ctx_loss) + (SEVERITY_LOSS_WEIGHT * sev_loss)

        bs = input_ids.size(0)
        total_loss += loss.item() * bs
        total_samples += bs

        ctx_preds = ctx_logits.argmax(dim=-1)
        sev_preds = sev_logits.argmax(dim=-1)
        ctx_correct += (ctx_preds == ctx_labels).sum().item()
        sev_correct += (sev_preds == sev_labels).sum().item()

        # Per-class
        for i in range(bs):
            label = ctx_labels[i].item()
            pred = ctx_preds[i].item()
            class_total[label] += 1
            if pred == label:
                class_correct[label] += 1

    avg_loss = total_loss / total_samples
    ctx_acc = ctx_correct / total_samples * 100
    sev_acc = sev_correct / total_samples * 100

    # Per-class breakdown
    logger.info("")
    logger.info("  ┌────────────────────────┬──────────┬────────────┐")
    logger.info("  │ Context Class           │ Samples  │ Accuracy   │")
    logger.info("  ├────────────────────────┼──────────┼────────────┤")
    for i, label in enumerate(CONTEXT_LABELS):
        if class_total[i] > 0:
            acc = class_correct[i] / class_total[i] * 100
            logger.info(f"  │ {label:<22} │ {class_total[i]:>6}   │ {acc:>8.1f}%  │")
        else:
            logger.info(f"  │ {label:<22} │ {0:>6}   │      N/A   │")
    logger.info("  └────────────────────────┴──────────┴────────────┘")

    return {
        "val_loss": avg_loss,
        "val_context_acc": ctx_acc,
        "val_severity_acc": sev_acc,
    }


# ═════════════════════════════════════════════════════════════
#                    LR FINDER
# ═════════════════════════════════════════════════════════════

def lr_find(model, train_loader, ctx_criterion, sev_criterion, logger):
    """Learning rate range test to find optimal LR.

    Starts at LR_FIND_MIN, multiplies LR each step, tracks loss.
    Based on "Cyclical Learning Rates for Training Neural Networks" (Smith, 2017).
    """
    logger.info("\n" + "=" * 60)
    logger.info("  🔬 LR Range Test")
    logger.info("=" * 60)

    model.train()
    losses = []
    lrs = []

    # Create temp optimizer with starting LR
    temp_optimizer = AdamW(
        [p for p in model.parameters() if p.requires_grad],
        lr=LR_FIND_MIN, weight_decay=WEIGHT_DECAY,
    )

    logger.info(f"  Starting LR: {LR_FIND_MIN:.2e}, multiplier: {LR_FIND_STEP_MULTIPLIER}")
    logger.info(f"  Running on {len(train_loader)} batches...\n")

    for step, batch in enumerate(train_loader):
        current_lr = LR_FIND_MIN * (LR_FIND_STEP_MULTIPLIER ** step)
        if current_lr > LR_FIND_MAX:
            break

        for param_group in temp_optimizer.param_groups:
            param_group["lr"] = current_lr

        input_ids = batch["input_ids"].to(DEVICE)
        attention_mask = batch["attention_mask"].to(DEVICE)
        ctx_labels = batch["context_label"].to(DEVICE)
        sev_labels = batch["severity_label"].to(DEVICE)

        temp_optimizer.zero_grad()

        with autocast(device_type=DEVICE.type, enabled=USE_AMP):
            ctx_logits, sev_logits = model(input_ids, attention_mask)
            ctx_loss = ctx_criterion(ctx_logits, ctx_labels)
            sev_loss = sev_criterion(sev_logits, sev_labels)
            loss = (CONTEXT_LOSS_WEIGHT * ctx_loss) + (SEVERITY_LOSS_WEIGHT * sev_loss)

        loss.backward()
        temp_optimizer.step()

        losses.append(loss.item())
        lrs.append(current_lr)

        if (step + 1) % 20 == 0:
            logger.info(f"  Step {step+1:>4} | LR: {current_lr:.2e} | Loss: {loss.item():.4f}")

    # Find optimal LR range
    if len(losses) > 10:
        smoothed = []
        window = max(1, len(losses) // 20)
        for i in range(len(losses)):
            start = max(0, i - window)
            end = min(len(losses), i + window + 1)
            smoothed.append(sum(losses[start:end]) / (end - start))

        # Find steepest negative gradient (loss decreasing fastest)
        deltas = [-(smoothed[i] - smoothed[i-1]) for i in range(1, len(smoothed))]
        start_idx = len(deltas) // 10
        end_idx = len(deltas) * 9 // 10

        if start_idx < end_idx and max(deltas[start_idx:end_idx]) > 0:
            best_idx = start_idx + deltas[start_idx:end_idx].index(max(deltas[start_idx:end_idx]))
            best_lr = lrs[best_idx + 1]

            logger.info(f"\n  ✅ Recommended LR range:")
            logger.info(f"     Minimum:    {best_lr / 10:.2e}")
            logger.info(f"     Suggested:  {best_lr:.2e}")
            logger.info(f"     Maximum:    {best_lr * 2:.2e}")
        else:
            logger.info(f"\n  ⚠  No clear LR optimum found (loss didn't decrease consistently)")

    # Save results
    results = {"learning_rates": lrs, "losses": losses}
    results_path = CHECKPOINT_DIR / "lr_find_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"\n  💾 LR find results saved → {results_path}")
    logger.info(f"\n  📊 Plot with: python -c \"import json, matplotlib.pyplot as plt; d=json.load(open('{results_path}')); plt.semilogx(d['learning_rates'], d['losses']); plt.grid(); plt.savefig('lr_find.png')\"")

    del temp_optimizer
    if DEVICE.type == "cuda":
        torch.cuda.empty_cache()
    return lrs, losses


# ═════════════════════════════════════════════════════════════
#                         MAIN
# ═════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="RedSentinel AI — Train XSS Classifier")
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--batch_size", type=int, default=BATCH_SIZE)
    parser.add_argument("--lr", type=float, default=LEARNING_RATE)
    parser.add_argument("--patience", type=int, default=PATIENCE)
    parser.add_argument("--no_class_weights", action="store_true", help="Disable class weighting")
    parser.add_argument("--resume", action="store_true", help="Resume from latest.pt")
    parser.add_argument("--lr-find", action="store_true", help="Run LR range test and exit")
    parser.add_argument("--sweep", action="store_true", help="Run Optuna hyperparameter sweep instead of single training")
    parser.add_argument("--n-trials", "--n_trials", type=int, default=None,
                        help="Number of sweep trials (default: from config)")
    parser.add_argument("--study", type=str, default=None,
                        help="Optuna study name for sweep (default: from config)")
    args = parser.parse_args()

    # ── Setup ──
    logger = setup_logging()

    logger.info("")
    logger.info("=" * 60)
    logger.info("  RedSentinel AI — Training Pipeline")
    logger.info("=" * 60)
    logger.info(f"  Device:          {DEVICE}")
    logger.info(f"  Epochs:          {args.epochs}")
    logger.info(f"  Batch size:      {args.batch_size}")
    logger.info(f"  LR:              {args.lr}")
    logger.info(f"  Patience:        {args.patience}")
    logger.info(f"  Label smooth:    {LABEL_SMOOTHING}")
    logger.info(f"  Loss weights:    ctx={CONTEXT_LOSS_WEIGHT}, sev={SEVERITY_LOSS_WEIGHT}")
    logger.info(f"  Freeze layers:   {FREEZE_LAYERS}")
    logger.info(f"  Joint head:      {JOINT_HEAD}")
    logger.info(f"  Class weights:   {not args.no_class_weights}")
    logger.info(f"  Dataset:         {TRAIN_FILE}")
    logger.info(f"  Runs logged to:  {RUN_LOG_DIR}")

    # ── Data ──
    train_loader, val_loader, _ = get_dataloaders(args.batch_size)

    # ── Model ──
    model = build_model()

    # ── Experiment Tracking ──
    run_logger = RunLogger({"learning_rate": args.lr, "epochs": args.epochs})
    logger.info(f"\n  📝 Run: {run_logger.path.name}")

    # ── Optimizer ──
    trainable_params = [p for p in model.parameters() if p.requires_grad]
    optimizer = AdamW(
        trainable_params,
        lr=args.lr,
        weight_decay=WEIGHT_DECAY,
        betas=(0.9, 0.999),
        eps=1e-8,
    )

    # ── Scheduler ──
    total_steps = len(train_loader) * args.epochs
    warmup_steps = int(total_steps * WARMUP_RATIO)
    scheduler = get_scheduler(optimizer, warmup_steps, total_steps)
    logger.info(f"\n  📊 Steps: {total_steps} total, {warmup_steps} warmup")

    # ── Loss with Class Weights ──
    if args.no_class_weights:
        ctx_weight = None
        sev_weight = None
        logger.info("\n  ⚖️ Class weights: disabled (--no_class_weights)")
    else:
        logger.info("\n  ⚖️ Computing class weights for imbalanced dataset...")
        df = pd.read_csv(TRAIN_FILE)

        ctx_counts = Counter(df["context"].str.strip().str.lower())
        total_ctx = sum(ctx_counts.values())
        n_ctx = len(CONTEXT_LABELS)
        ctx_weight = torch.tensor([
            total_ctx / (n_ctx * ctx_counts.get(label, 1))
            for label in CONTEXT_LABELS
        ], dtype=torch.float, device=DEVICE)

        sev_counts = Counter(df["severity"].str.strip().str.lower())
        total_sev = sum(sev_counts.values())
        n_sev = len(SEVERITY_LABELS)
        sev_weight = torch.tensor([
            total_sev / (n_sev * sev_counts.get(label, 1))
            for label in SEVERITY_LABELS
        ], dtype=torch.float, device=DEVICE)

        ctx_str = ", ".join(f"{l}={w:.2f}" for l, w in zip(CONTEXT_LABELS, ctx_weight.tolist()))
        sev_str = ", ".join(f"{l}={w:.2f}" for l, w in zip(SEVERITY_LABELS, sev_weight.tolist()))
        logger.info(f"    Context:  [{ctx_str}]")
        logger.info(f"    Severity: [{sev_str}]")

    ctx_criterion = nn.CrossEntropyLoss(weight=ctx_weight, label_smoothing=LABEL_SMOOTHING)
    sev_criterion = nn.CrossEntropyLoss(weight=sev_weight, label_smoothing=LABEL_SMOOTHING)

    # ── LR Finder ──
    if args.lr_find:
        lr_find(model, train_loader, ctx_criterion, sev_criterion, logger)
        return

    # ── Hyperparameter Sweep ──
    if args.sweep:
        logger.info("\n  🔬 Delegating to Optuna sweep...")
        # Import sweep module and run
        from sweep import run_sweep
        run_sweep(
            study_name=args.study or SWEEP_STUDY_NAME,
            n_trials=args.n_trials or SWEEP_N_TRIALS,
        )
        return

    # ── AMP Scaler ──
    scaler = (
        GradScaler(device=DEVICE.type)
        if USE_AMP and DEVICE.type == "cuda"
        else None
    )

    # ── Metrics ──
    metrics = MetricsTracker()

    # ── Resume ──
    start_epoch = 0
    best_val_loss = float("inf")

    if args.resume:
        latest = CHECKPOINT_DIR / "latest.pt"
        if latest.exists():
            start_epoch, best_val_loss = load_checkpoint(latest, model, optimizer, scheduler, scaler)
            start_epoch += 1
            logger.info(f"\n  ⏩ Resumed from epoch {start_epoch}, best val loss: {best_val_loss:.4f}")
        else:
            logger.info("\n  ⚠ No checkpoint found — starting fresh")

    # ── Early Stopping ──
    patience_counter = 0

    # ══════════════════════════════════════════════════════
    #                  TRAINING LOOP
    # ══════════════════════════════════════════════════════

    logger.info("\n" + "=" * 60)
    logger.info("  🚀 Starting Training")
    logger.info("=" * 60)

    total_start = time.time()

    for epoch in range(start_epoch, args.epochs):
        logger.info(f"\n{'─' * 60}")
        logger.info(f"  📌 Epoch {epoch + 1}/{args.epochs}")
        logger.info(f"{'─' * 60}")

        # ── Train ──
        logger.info("\n  📈 Training...")
        train_metrics = train_one_epoch(
            model, train_loader, optimizer, scheduler, scaler,
            ctx_criterion, sev_criterion, epoch, logger
        )
        logger.info(
            f"\n  Train → Loss: {train_metrics['train_loss']:.4f} | "
            f"Ctx: {train_metrics['train_context_acc']:.1f}% | "
            f"Sev: {train_metrics['train_severity_acc']:.1f}% | "
            f"Time: {train_metrics['epoch_time']:.1f}s"
        )

        # ── Validate ──
        logger.info("\n  📊 Validating...")
        val_metrics = validate(model, val_loader, ctx_criterion, sev_criterion, logger)
        logger.info(
            f"\n  Val   → Loss: {val_metrics['val_loss']:.4f} | "
            f"Ctx: {val_metrics['val_context_acc']:.1f}% | "
            f"Sev: {val_metrics['val_severity_acc']:.1f}%"
        )

        # ── Record ──
        all_metrics = {**train_metrics, **val_metrics}
        metrics.record(all_metrics)
        metrics.save(CHECKPOINT_DIR / "metrics.json")
        run_logger.log_epoch(epoch, all_metrics)

        # ── Save latest ──
        save_checkpoint(
            model, optimizer, scheduler, scaler,
            epoch, val_metrics["val_loss"],
            CHECKPOINT_DIR / "latest.pt"
        )

        # ── Save periodic ──
        if (epoch + 1) % SAVE_EVERY_N_EPOCHS == 0:
            save_checkpoint(
                model, optimizer, scheduler, scaler,
                epoch, val_metrics["val_loss"],
                CHECKPOINT_DIR / f"epoch_{epoch + 1}.pt"
            )

        # ── Best model? ──
        if val_metrics["val_loss"] < best_val_loss:
            improvement = best_val_loss - val_metrics["val_loss"]
            best_val_loss = val_metrics["val_loss"]
            patience_counter = 0

            save_checkpoint(
                model, optimizer, scheduler, scaler,
                epoch, val_metrics["val_loss"],
                CHECKPOINT_DIR / "best.pt"
            )
            logger.info(f"\n  ✅ New best! Val loss improved by {improvement:.4f}")
            logger.info(f"     Saved → {CHECKPOINT_DIR / 'best.pt'}")
        else:
            patience_counter += 1
            logger.info(f"\n  ⏳ No improvement. Patience: {patience_counter}/{args.patience}")

        # ── Early stop? ──
        if patience_counter >= args.patience:
            logger.info(f"\n  🛑 Early stopping at epoch {epoch + 1}")
            break

    # ══════════════════════════════════════════════════════
    #                    DONE
    # ══════════════════════════════════════════════════════

    total_time = time.time() - total_start

    logger.info("\n" + "=" * 60)
    logger.info("  🏁 Training Complete!")
    logger.info("=" * 60)
    logger.info(f"  Total time:       {total_time / 60:.1f} minutes")
    logger.info(f"  Best val loss:    {best_val_loss:.4f}")

    if metrics.history["val_context_acc"]:
        logger.info(f"  Best context acc: {max(metrics.history['val_context_acc']):.1f}%")
    if metrics.history["val_severity_acc"]:
        logger.info(f"  Best severity acc: {max(metrics.history['val_severity_acc']):.1f}%")

    logger.info(f"  Checkpoints:      {CHECKPOINT_DIR}")
    logger.info(f"  Metrics:          {CHECKPOINT_DIR / 'metrics.json'}")
    logger.info(f"  Run logs:         {run_logger.path / 'metrics.csv'}")
    logger.info(f"  Config:           {run_logger.path / 'config.json'}")

    # ── Summary table ──
    logger.info("\n  Epoch Summary:")
    logger.info("  ┌───────┬────────────┬────────────┬──────────┬──────────┐")
    logger.info("  │ Epoch │ Train Loss │  Val Loss  │ Ctx Acc  │ Sev Acc  │")
    logger.info("  ├───────┼────────────┼────────────┼──────────┼──────────┤")

    for i in range(len(metrics.history["train_loss"])):
        tl = metrics.history["train_loss"][i]
        vl = metrics.history["val_loss"][i]
        ca = metrics.history["val_context_acc"][i]
        sa = metrics.history["val_severity_acc"][i]
        best = " ◀" if vl == best_val_loss else ""
        logger.info(
            f"  │  {i+1:>3}  │  {tl:.4f}   │  {vl:.4f}   │ {ca:>5.1f}%  │ {sa:>5.1f}%  │{best}"
        )

    logger.info("  └───────┴────────────┴────────────┴──────────┴──────────┘")
    logger.info("")


if __name__ == "__main__":
    main()