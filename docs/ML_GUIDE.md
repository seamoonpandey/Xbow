# ML Guide

This is the canonical guide for RedSentinel model, dataset, and ML-runtime ownership.

---

## Current Assets

```text
dataset/splits/                 Train/val/test payload splits used by payload-gen
dataset/processed/              Curated and enriched payload data
dataset/ranker_training/        Ranker training samples and related data when present
model/tokenizer/                Tokenizer used by the context classifier
model/ranker/                   XGBoost ranker model artifacts and metrics when present
model/checkpoints/metrics.json  Small tracked checkpoint summary
model/checkpoints/test_results.json
ai/training/                    Training scripts for neural models
tools/inference/                Offline inference, inspection, calibration, export
training_data volume            Runtime fuzzer-collected samples in Docker Compose
```

Large checkpoint binaries under `model/checkpoints/*.pt` are intentionally ignored. Keep them local, mount them in containers, or publish them as release artifacts instead of committing them.

---

## Runtime Behavior

### Context classifier

The context module exposes `GET /health` with `ai_model_loaded`. When the model is unavailable, the classifier code should fall back rather than making the service unavailable. Do not document the classifier as always backed by a loaded DistilBERT checkpoint unless the deployment includes the required artifacts.

### Payload ranker

The payload-gen module attempts to load an XGBoost ranker from `model/ranker/`.

- When the model is loaded, `/health` reports `"ranker": "xgboost"`.
- When the model is missing or cannot load, `/health` reports `"ranker": "heuristic"` and payload ranking falls back to heuristic scoring.
- `GET /ranker/info` returns `model_loaded`, `ranker_type`, and `feature_importance`.

Canonical wording:

> Payload ranking uses XGBoost when the ranker model is available; otherwise it falls back to heuristic scoring.

Do not claim ranking is always XGBoost-powered.

---

## Dataset Sources

Keep dataset-source lists consistent with `dataset/README.md`. Current documented sources are:

- AwesomeXSS
- PayloadsAllTheThings
- XSSGAI
- PortSwigger XSS cheat sheet content

Use “approximately 59K+” for payload-bank size unless an exact count is directly proven by a tracked file or reproducible script output. Do not hard-code exact values such as 59,122 in canonical docs unless the repository proves that number at the time of the documentation change.

---

## Data Flow

1. Raw third-party payload collections are cloned or downloaded locally under `dataset/raw/`; this directory is ignored.
2. Dataset scripts in `dataset/` produce curated data under `dataset/processed/` and split files under `dataset/splits/`.
3. Training scripts under `ai/training/` consume processed/split data.
4. Runtime services consume mounted/tracked artifacts:
   - context module: `model/`
   - payload-gen module: `dataset/splits/` and `model/ranker/`
   - fuzzer module: `training_data` volume for collected samples
5. Offline tools under `tools/inference/` write generated outputs to `outputs/`, which is ignored except for `.gitkeep`.

---

## Context and Label Taxonomies

Do not describe RedSentinel as having one universal six-class taxonomy.

Runtime reflection contexts can include labels such as:

- `html_body`
- `attribute`
- `js_string`
- `js_block`
- `url`
- `none`

Payload-gen and fuzzer payload objects also carry context strings and finding metadata. Vulnerability/finding labels are separate and can include values such as:

- `reflected_xss`
- `stored_xss`
- `dom_xss`
- `dom_stored_xss`
- `template_injection`
- `svg_xss`
- `mutation_xss`

Training/evaluation datasets may use narrower or broader labels depending on the script. Document those as training labels, not as the only runtime taxonomy.

---

## Active Maintenance Rules

- Update `dataset/README.md` when dataset generation or source collection changes.
- Update this file when model ownership, artifact paths, ranker behavior, or training flow changes.
- Keep detailed experiments in `docs/evaluation/` only when they support a current tracked evaluation report.
- Keep generated charts under `docs/evaluation/charts/` only when they support a tracked evaluation report.
- Keep archived experiments and old plans under `docs/archive/` and treat them as historical.

---

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

Only report these commands as successful after running them in the current environment.
