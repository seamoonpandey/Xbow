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
