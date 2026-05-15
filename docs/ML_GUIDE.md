# ML Guide

This is the canonical guide for RedSentinel model and dataset ownership.

## Current Assets

```text
dataset/splits/                 Train/val/test payload splits used by services
dataset/processed/              Curated and enriched payload data
dataset/ranker_training/        Ranker training samples
model/tokenizer/                Tokenizer used by the context classifier
model/ranker/                   XGBoost ranker model and metrics
model/checkpoints/metrics.json  Small tracked checkpoint summary
model/checkpoints/test_results.json
ai/training/                    Training scripts for neural models
tools/inference/                Offline inference, inspection, calibration, export
```

Large checkpoint binaries under `model/checkpoints/*.pt` are intentionally
ignored. Keep them local, mount them in containers, or publish them as release
artifacts instead of committing them.

## Data Flow

1. Raw third-party payload collections are cloned or downloaded locally under
   `dataset/raw/`; this directory is ignored.
2. Dataset scripts in `dataset/` produce curated CSVs under
   `dataset/processed/` and split files under `dataset/splits/`.
3. Training scripts under `ai/training/` consume the processed/split data.
4. Runtime services consume small, curated artifacts:
   `dataset/splits/`, `model/tokenizer/`, and `model/ranker/`.
5. Offline tools under `tools/inference/` write generated outputs to
   `outputs/`, which is ignored except for `.gitkeep`.

## Active Maintenance Rules

- Update `dataset/README.md` when dataset generation changes.
- Update this file when model ownership, artifact paths, or training flow
  changes.
- Keep detailed experiments in `docs/evaluation/` if they are current.
- Keep generated charts under `docs/evaluation/charts/` only when they support
  a tracked evaluation report.

## Useful Commands

```bash
# Generate dataset evaluation tables
python scripts/generate_dataset_tables.py

# Run single-payload inference
python tools/inference/infer.py \
  --payload "<script>alert(1)</script>" \
  --checkpoint model/checkpoints/best.pt \
  --tokenizer model/tokenizer

# Calibrate model confidence
python tools/inference/calibration.py \
  --val_csv dataset/splits/val.csv \
  --checkpoint model/checkpoints/best.pt \
  --tokenizer model/tokenizer \
  --out outputs/temps.json
```
