# ML Guide

This is the canonical guide for RedSentinel model, dataset, and ML-runtime ownership.

---

## Current Assets

```text
dataset/splits/                 Train/val/test payload splits used by payload-gen
dataset/processed/              Curated and enriched payload data
dataset/ranker_training/        Ranker training samples and related data when present
dataset/dataset_manifest.json   Reproducible artifact manifest (SHA-256 checksums, row counts)
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

## Validation vs Test Discrepancy

`model/checkpoints/metrics.json` reports validation metrics logged during training on the val set (`dataset/processed/splits_from_ranker/val.csv`). `model/checkpoints/test_results.json` reports evaluation metrics on a held-out test set.

| Metric | Validation | Test (old, stale) | Test (current, clean) |
| -------- | -----------: | -----------------: | ----------------------: |
| Context accuracy | ~75.1% | 99.53% | **78.4%** |
| Severity accuracy | ~35.4% | 99.56% | **38.2%** |
| Samples | 489 | 3,632 | **306** |

**✅ The discrepancy is now resolved.** With clean splits and regenerated `test_results.json`, the test metrics (78.4% context, 38.2% severity) are consistent with the validation metrics (75.1% / 35.4%). The remaining gap is explained by the model's inherent performance and label quality, not by data leakage.

The old results (99.53%/99.56% on 3,632 samples) were inflated by data leakage — 78% of test payloads appeared in training, so the test measured memorization rather than generalization.

### 1. Sample-count resolved

The current test split (`splits_from_ranker/test.csv`) has 421 data rows (82 unique payloads). After filtering for known labels, the evaluation loads **306 valid test samples**. This is consistent with the split size.

The old `test_results.json` reported 3,632 samples — it was generated from a different, larger test set. It has now been **regenerated** (2026-03-13) with the current clean splits.

### 2. Massive data leakage in current splits

> **Historical analysis (original splits, before regeneration).** Current splits have **zero** payload overlap — see Action #1 below.

The original splits under `splits_from_ranker/` had severe payload overlap between sets:

| Overlap type | Train-Val | Train-Test |
|---|---|---|
| Duplicate payloads (exact) | 83.1% | 78.2% |
| Duplicate (payload, context) pairs | 64.4% | 57.7% |
| Duplicate (payload, context, severity) triples | 53.4% | 52.5% |
| Near-duplicate (normalized) test payloads in train | — | 83.4% |

**161 of 206 unique test payloads (78%) appear in the training set.** 422 of 471 test rows use payloads already seen during training. Even test payloads with novel normalized forms retain ~0.91 average string similarity to their closest training match. This means the test set largely tests *memorization* rather than *generalization*. The model can predict test labels by recalling the most common label assigned to each payload during training, rather than learning to infer context from syntactic features.

### 3. Label noise in validation set (severity)

> **Historical analysis.** The old (stale) test set claimed 99.56% severity accuracy, but the current clean test set shows **38.2%**, consistent with validation's ~35.4%.

Severity accuracy peaks at only ~35% during validation (and ~38% on the clean test set), well below the context accuracy. Possible causes:
- Severity labels in the dataset are noisy or inconsistent
- The model has not learned to predict severity from payload syntax alone (severity is often context-dependent and requires runtime evidence)
- Severity labels were assigned by different heuristics for different portions of the data (e.g., automated rules vs manual labeling)

### 4. Synthetic test data predictability

> **Historical analysis.** The 83.4% normalized overlap and the inflated test scores were artifacts of the original overlapping splits. With zero-overlap splits, the current test set (78.4% context, 38.2% severity) reflects genuine model generalization.

Test payloads tend to show stereotyped syntax-to-context mappings (e.g., `{{7*7}}` → `template_injection`, `<svg/onload=...>` → `tag_injection`). If these patterns were trivially repeated across splits, the test would be artificially easy — the original overlapping splits confirmed this (83.4% normalized overlap). With clean splits, the model's 78% context accuracy on unfamiliar payloads is a realistic estimate of generalization performance.

### 5. Different checkpoint possibilities

`metrics.json` logs metrics **during training** using the latest model state after each epoch. The best model is saved as `best.pt`. If `test_results.json` was generated from a different checkpoint (e.g., `latest.pt` after more training, or an older `best.pt` from a different training run), the results would differ. The checkpoint metadata in `test_results.json` does not record which checkpoint was used.

### 6. Label task consistency

Both files use the same label taxonomy (8 context classes, 3 severity classes defined in `config.py`). However, the validation metrics show per-class accuracy varying widely — some classes may have very few or zero validation examples, making aggregate metrics misleading. The test results do not report per-class accuracy, making it impossible to verify whether the high scores are uniform or driven by dominant classes.

### Data-leakage checks

**Before regeneration (historical):**

| Check | Result |
|-------|--------|
| Exact duplicate payloads across train/test | **78.2%** of test payloads seen in train |
| Exact duplicate triples across train/test | **52.5%** of test triples seen in train |
| Near-duplicate (normalized) test payloads in train | **83.4%** |
| Average string similarity of novel test payloads to train | **0.907** |
| Same source pages across train/test | Cannot determine — no source-page metadata in splits |

**After regeneration (current state):**

| Check | Result |
|-------|--------|
| Exact duplicate payloads across train/val/test | **0** — zero overlap across all split pairs |
| Same source pages across train/test | Cannot determine — no source-page metadata in splits |

### Recommended Actions

1. ✅ **Regenerated clean splits** (2026-03-13) — zero payload overlap between train/val/test. Strategy: grouped all rows by unique payload, split payloads 70/15/15 stratified by dominant context label, then assigned all rows for a given payload to the same split. Results: **0** duplicate payloads across all pairs.
2. ✅ **Re-ran evaluation** (2026-03-13) — `test_results.json` updated with clean splits using checkpoint `best.pt`. Results are consistent with validation metrics.
3. **Investigate severity labels** — 35% validation accuracy suggests label quality issues requiring manual audit.
4. **Add data-leakage checks** to the dataset pipeline (e.g., in `scripts/dataset_stats.py` or a standalone validation script).
5. ✅ **Per-class metrics are now available** via confusion matrix and error breakdown in `test_results.json`. Could be further structured into a dedicated per-class metrics table in the JSON output.
6. **Record evaluation metadata** in `test_results.json`: checkpoint path, config used, timestamp.

---

## Dataset Pipeline

The dataset pipeline is automated via the project Makefile. See `dataset/README.md` for full details.

| Target | Action |
|---|---|
| `make dataset` | Rebuild all processed CSVs & splits from raw sources |
| `make dataset-report` | Run `scripts/dataset_stats.py` + regenerate `dataset/dataset_manifest.json` |
| `make dataset-all` | Both of the above |

### Key scripts

- **`dataset/collect_payloads.py`** — Collects raw payloads from upstream collections
- **`dataset/collect_portswigger.py`** — Extracts PortSwigger cheat-sheet payloads
- **`dataset/label_contexts.py`** — Labels payloads with context, severity, technique
- **`dataset/generate_synthetic.py`** — Generates synthetic/obfuscated payload variants
- **`dataset/finalize_dataset.py`** — Deduplicates, filters, and creates train/val/test splits
- **`scripts/dataset_stats.py`** — Reproducible 12-section statistics report (see below)
- **`scripts/generate_dataset_manifest.py`** — Produces `dataset/dataset_manifest.json`

### Dataset statistics (`scripts/dataset_stats.py`)

The stats script produces a 12-section report covering:

| Section | Content |
|---|---|
| 1 | Raw collection counts from each source |
| 2 | Labeling stage counts and PortSwigger overlap |
| 3 | Synthetic generation counts |
| 4 | Finalization and deduplication |
| 5 | Validity filter and label filter |
| 6 | Train/val/test split distribution |
| 7 | **Payload-family balance** — dominant XSS pattern families |
| 8 | **Encoding & obfuscation categories** — 12 encoding technique prevalence |
| 9 | Class distribution by context, severity, source |
| 10 | Executable/verified payloads from ranker training |
| 11 | Summary with authoritative payload bank size |
| 12 | **Real-World Application Coverage Analysis** — maps payloads to 14 exploitable sink types, cross-references browser-verified samples per context, provides coverage assessment |

### Dataset manifest

`dataset/dataset_manifest.json` records SHA-256 checksums, row counts, source repo metadata, and script versions for every artifact in the pipeline. The manifest is the authoritative source for data integrity verification.

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

The curated payload-bank size is **59,122** (proven by `scripts/dataset_stats.py` Section 11 and `dataset/dataset_manifest.json`). Update this exact number when `dataset_stats.py` outputs a different count.

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
6. **Reproducible verification**: `make dataset-report` runs `scripts/dataset_stats.py` and `scripts/generate_dataset_manifest.py` to produce the stats report and `dataset/dataset_manifest.json`.

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
- Update `scripts/dataset_stats.py` when new analysis sections are added to the dataset.
- Update `scripts/generate_dataset_manifest.py` when pipeline scripts or tracked artifacts change.
- Update `Makefile` when new pipeline steps or workflow targets are added.
- Update this file when model ownership, artifact paths, ranker behavior, or training flow changes.
- Regenerate `dataset/dataset_manifest.json` after any dataset rebuild (`make dataset-report`).
- Keep detailed experiments in `docs/evaluation/` only when they support a current tracked evaluation report.
- Keep generated charts under `docs/evaluation/charts/` only when they support a tracked evaluation report.
- Keep archived experiments and old plans under `docs/archive/` and treat them as historical.

---

## Useful Commands

```bash
# Generate dataset statistics report + manifest
make dataset-report

# Rebuild entire dataset from raw sources
make dataset

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
