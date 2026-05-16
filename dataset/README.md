# Dataset

This directory contains XSS payload data used by RedSentinel for payload generation, model training/evaluation, and related maintenance scripts.

Use “approximately 59K+” for the curated payload-bank size unless a currently tracked artifact or reproducible script output proves a more exact number.

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

## Directory Roles

```text
dataset/raw/              Local cloned/downloaded upstream sources; ignored by Git
dataset/processed/        Curated and enriched payload data
dataset/splits/           Runtime train/validation/test split files used by payload-gen
dataset/ranker_training/  Ranker training data when generated
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
