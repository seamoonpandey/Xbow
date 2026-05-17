# Dataset

This directory contains XSS payload data used by RedSentinel for payload generation, model training/evaluation, and related maintenance scripts.

The curated payload-bank size is **59,122** (proven by `scripts/dataset_stats.py` Section 11 and `dataset/dataset_manifest.json`).

---

## Data Sources

The documented dataset sources are:

### AwesomeXSS

Collection of XSS attack vectors and test cases gathered from security research and vulnerability databases.

Repository: `https://github.com/s0md3v/AwesomeXSS`

### PayloadsAllTheThings

Community-maintained payload repository used by penetration testers and security researchers.

Repository: `https://github.com/swisskyrepo/PayloadsAllTheThings`

### XSSGAI

XSS payload data used for automated analysis and ML-oriented vulnerability-detection experiments.

Repository: `https://github.com/AnonKryptiQuz/XSSGAI`

### PortSwigger XSS Cheat Sheet

PortSwigger XSS cheat-sheet content is downloaded as raw HTML and used as an additional payload/source reference.

Source: `https://portswigger.net/web-security/cross-site-scripting/cheat-sheet`

---

## Reproducible Pipeline

The dataset pipeline is fully reproducible via the project Makefile. All scripts under `dataset/` and `scripts/` produce deterministic output from raw sources.

### Build from raw sources

```bash
# Requires dataset/raw/ to be populated (see "Download Raw Sources" below)
make dataset
```

This runs the pipeline in order:

1. **`dataset/collect_payloads.py`** — Collects raw payloads from AwesomeXSS, XSSGAI, PayloadsAllTheThings clones
2. **`dataset/collect_portswigger.py`** — Extracts payloads from the PortSwigger cheat-sheet HTML
3. **`dataset/label_contexts.py`** — Labels each payload with context, severity, and technique
4. **`dataset/generate_synthetic.py`** — Generates synthetic/obfuscated payload variants
5. **`dataset/finalize_dataset.py`** — Deduplicates, filters, and splits into train/val/test CSVs

### Generate report and manifest

```bash
make dataset-report
```

This runs two scripts:

- **`scripts/dataset_stats.py`** — Reads the actual CSV files on disk and produces a 12-section reproducible statistics report covering raw collection counts, deduplication, validity filtering, class distribution, payload-family balance (Section 7), encoding/obfuscation categories (Section 8), executable/verified payloads from ranker training (Section 10), and real-world application coverage analysis (Section 12).
- **`scripts/generate_dataset_manifest.py`** — Writes `dataset/dataset_manifest.json` with SHA-256 checksums, row counts, source repository metadata, and script version tracking.

### Combined

```bash
make dataset-all    # Rebuild pipeline + generate report and manifest
```

---

## Dataset Manifest

`dataset/dataset_manifest.json` is the reproducible record of every artifact in the pipeline. It contains:

- **sources** — URLs, download dates, and commit SHAs for each raw upstream source
- **scripts** — Git commit SHA and date for every pipeline script
- **artifacts** — SHA-256 checksums, row counts, and sizes for all 13 processed/split/ranker files
- **pipeline_order** — The canonical script execution sequence
- **project_repo_sha** — Git commit of the RedSentinel repo at generation time

The manifest is the authoritative source for verifying data integrity. Any report citing a dataset count SHOULD reference the manifest or the output of `scripts/dataset_stats.py`.

---

## Coverage Analysis (Section 12)

`scripts/dataset_stats.py` Section 12 maps the curated payload bank against 14 exploitable sink types (html_injection, event_handler_injection, javascript_uri, js_string_escape, attribute_breakout, textarea_escape, etc.), cross-references 8,976+ browser-verified samples from ranker training across contexts, and provides an overall coverage strength assessment.

This analysis demonstrates what percentage of the payload bank maps to real-world vulnerable application endpoints (see `exploitable/app.py` for the target application).

---

## Directory Roles

```text
dataset/raw/              Local cloned/downloaded upstream sources; ignored by Git
dataset/processed/        Curated and enriched payload data
dataset/splits/           Runtime train/validation/test split files used by payload-gen
dataset/ranker_training/  Ranker training data when generated

# Scripts
scripts/dataset_stats.py              Reproducible statistics report (12 sections)
scripts/generate_dataset_manifest.py   Manifest generator (checksums + metadata)
Makefile                               Pipeline automation (make dataset / make dataset-report)
```

Docker Compose mounts `./dataset/splits` into the payload-gen container at `/app/dataset/splits`. If the mounted split files are missing or the bank loads empty, the payload-gen `/generate` endpoint returns 503.

---

## Runtime Use

The payload-gen module loads its payload bank from the configured dataset directory, usually `DATASET_DIR=/app/dataset/splits` in Docker or `DATASET_DIR=../../dataset/splits` for local manual execution.

Payload selection and ranking are context-aware, but ranking is not always ML-backed:

- XGBoost is used when the ranker model under `model/ranker/` loads successfully.
- Heuristic ranking is used when the ranker model is missing or unavailable.

---

## Context and Label Notes

Do not treat any one label set as the only taxonomy for the whole project.

Runtime reflection contexts include labels such as `html_body`, `attribute`, `js_string`, `js_block`, `url`, and `none`.

Finding/vulnerability labels are separate and can include labels such as `reflected_xss`, `stored_xss`, `dom_xss`, `dom_stored_xss`, `template_injection`, `svg_xss`, and `mutation_xss`.

Training/evaluation files may use narrower label sets depending on the script that produced them.

---

## Download Raw Sources

Raw sources are local inputs and are not committed.

```bash
mkdir -p dataset/raw
cd dataset/raw \
&& git clone https://github.com/s0md3v/AwesomeXSS \
&& git clone https://github.com/swisskyrepo/PayloadsAllTheThings \
&& git clone https://github.com/AnonKryptiQuz/XSSGAI \
&& curl -sL https://portswigger.net/web-security/cross-site-scripting/cheat-sheet \
  -o portswigger_raw.html
```

---

## Safety Note

This data is intended for authorized security research and defensive testing only. Do not use these payloads against systems without permission.
