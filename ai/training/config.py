# ai/training/config.py
"""
RedSentinel AI — Training Configuration
Corrected to match actual project structure.
"""

import os
import torch
from pathlib import Path

# ─── Paths (matching actual tree structure) ──────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent   # red-sentinel/
DATASET_DIR = PROJECT_ROOT / "dataset" / "splits"
MODEL_DIR = PROJECT_ROOT / "model"
CUSTOM_TOKENIZER_PATH = MODEL_DIR / "tokenizer" / "tokenizer.json"
CHECKPOINT_DIR = MODEL_DIR / "checkpoints"

# Create dirs
CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
(CHECKPOINT_DIR / "logs").mkdir(parents=True, exist_ok=True)

# ─── Dataset Splits (CSV files) ─────────────────────────
# Using the 60K combined dataset from finalize_dataset.py
# (synthetic + scraped payloads, properly labeled)
TRAIN_FILE = DATASET_DIR / "train.csv"
VAL_FILE = DATASET_DIR / "val.csv"
TEST_FILE = DATASET_DIR / "test.csv"

# ─── Tokenizer ──────────────────────────────────────────
# Using DistilBERT's tokenizer (matches pretrained backbone)
DISTILBERT_MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 128

# ─── Classification Labels (from your actual data) ──────
CONTEXT_LABELS = [
    "script_injection",    # 0
    "event_handler",       # 1
    "js_uri",              # 2
    "tag_injection",       # 3
    "template_injection",  # 4
    "dom_sink",            # 5
    "attribute_escape",    # 6
    "generic",             # 7
]

SEVERITY_LABELS = [
    "low",                 # 0
    "medium",              # 1
    "high",                # 2
]

CONTEXT_CLASSES = len(CONTEXT_LABELS)    # 8
SEVERITY_CLASSES = len(SEVERITY_LABELS)  # 3

# ─── Model Architecture ─────────────────────────────────
DROPOUT = 0.3
FREEZE_LAYERS = 0    # Don't freeze layers (XSS domain is far from natural language)
GRADIENT_CHECKPOINTING = True  # Recompute activations during backward vs storing.
                                # Saves ~50% activation memory on GPU at ~33%
                                # compute overhead. Disable if you have >6 GB VRAM.

# ─── Training Hyperparameters ────────────────────────────
EPOCHS = 15
BATCH_SIZE = 32
LEARNING_RATE = 2e-5
WEIGHT_DECAY = 0.01
WARMUP_RATIO = 0.1
MAX_GRAD_NORM = 1.0

# ─── Loss Weights ───────────────────────────────────────
CONTEXT_LOSS_WEIGHT = 0.7
SEVERITY_LOSS_WEIGHT = 0.3
LABEL_SMOOTHING = 0.1

# ─── Early Stopping ─────────────────────────────────────
PATIENCE = 5

# ─── GPU Memory & CPU Thread Optimization ────────────────
# On systems with limited/fragmented GPU memory (e.g. laptops
# where the display compositor shares VRAM), this setting helps
# PyTorch allocate memory in expandable segments rather than
# pre-allocating large contiguous blocks.
#
# This is also the default in PyTorch 2.5+.
PYTORCH_CUDA_ALLOC_CONF = "expandable_segments:True"

# Half of logical cores — empirically best for CPU training.
# Without this, PyTorch may oversubscribe threads, causing
# context-switching overhead.
OMP_NUM_THREADS = os.cpu_count() // 2

# ─── Checkpoint Behavior ───────────────────────────────────
# When True, only save best.pt and latest.pt (overwrite each
# epoch). Saves ~5.6 GB of disk over 15 epochs vs saving every
# epoch checkpoint.
SAVE_ONLY_BEST = True

# ─── Device ──────────────────────────────────────────────
def get_device():
    """Detect the best available compute device.

    Priority:
      1. MPS (Apple Silicon) — fastest on Mac M1+/M2+
      2. CUDA (NVIDIA GPU) — fastest on Linux/Windows
      3. CPU — fallback for all other systems
    """
    if torch.backends.mps.is_available() and torch.backends.mps.is_built():
        return torch.device("mps")

    if torch.cuda.is_available():
        return torch.device("cuda")

    return torch.device("cpu")

DEVICE = get_device()

# ─── Device-Aware Mixed Precision (AMP) ─────────────────
# AMP uses lower-precision float16 where mathematically safe to:
#   - Speed up training (2-3x on modern GPUs/accelerators)
#   - Reduce GPU memory usage (~half compared to float32)
#   - Maintain model accuracy (critical layers remain float32)
#
# Device support:
#   CUDA \u2192 Full AMP: autocast + GradScaler
#           (GradScaler prevents gradient underflow in float16)
#   MPS  \u2192 autocast supported (PyTorch \u22652.0)
#           No GradScaler needed \u2014 MPS handles scaling internally
#   CPU  \u2192 AMP not beneficial; always runs full float32 precision
USE_AMP = DEVICE.type in ("cuda", "mps")

# ─── Logging ─────────────────────────────────────────────
LOG_EVERY_N_STEPS = 50
SAVE_EVERY_N_EPOCHS = 1

# ─── Joint Head Architecture ──────────────────────────────
# Share a hidden layer between context and severity heads
# so that context learning benefits severity and vice versa.
JOINT_HEAD = True

# ─── Experiment Tracking ──────────────────────────────────
RUN_LOG_DIR = PROJECT_ROOT / "runs"
RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)

# ─── LR Finder ────────────────────────────────────────────
LR_FIND_MIN = 1e-7
LR_FIND_MAX = 1.0
LR_FIND_STEP_MULTIPLIER = 1.05   # Multiply LR by this each step

# ─── Optuna Hyperparameter Sweep ────────────────────────────
SWEEP_N_TRIALS = 20            # Number of trials per sweep
SWEEP_EPOCHS = 8               # Fewer epochs per trial for speed
SWEEP_PATIENCE = 3             # Aggressive early stopping for sweeps
SWEEP_STUDY_NAME = "redsentinel_xss_sweep"
SWEEP_TIMEOUT_MINUTES = 120    # Kill if a single sweep runs longer

# Search space boundaries
SWEEP_LR_MIN = 1e-6
SWEEP_LR_MAX = 1e-4
SWEEP_DROPOUT_MIN = 0.1
SWEEP_DROPOUT_MAX = 0.5
SWEEP_WARMUP_MIN = 0.0
SWEEP_WARMUP_MAX = 0.3
SWEEP_WEIGHT_DECAY_MIN = 1e-4
SWEEP_WEIGHT_DECAY_MAX = 1e-1
SWEEP_LABEL_SMOOTHING_MIN = 0.0
SWEEP_LABEL_SMOOTHING_MAX = 0.3
SWEEP_CTX_LOSS_WEIGHT_MIN = 0.3
SWEEP_CTX_LOSS_WEIGHT_MAX = 0.8


# ─── Print config on import ──────────────────────────────
def print_config():
    print("\n⚙️  Configuration:")
    print(f"  Project root:  {PROJECT_ROOT}")
    print(f"  Train file:    {TRAIN_FILE} (exists: {TRAIN_FILE.exists()})")
    print(f"  Val file:      {VAL_FILE} (exists: {VAL_FILE.exists()})")
    print(f"  Test file:     {TEST_FILE} (exists: {TEST_FILE.exists()})")
    print(f"  Checkpoint dir: {CHECKPOINT_DIR}")
    print(f"  Backbone:      {DISTILBERT_MODEL_NAME}")
    print(f"  Device:        {DEVICE}")
    print(f"  Context labels: {CONTEXT_LABELS}")
    print(f"  Severity labels: {SEVERITY_LABELS}")


if __name__ == "__main__":
    print_config()