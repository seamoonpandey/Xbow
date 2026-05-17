# ── RedSentinel Dataset — Makefile ─────────────────────────────────
#
# Reproducible dataset pipeline.  All targets run from project root.
#
# Usage:
#   make dataset-raw      Clone/download raw sources into dataset/raw/
#   make dataset          Rebuild processed CSVs & splits from raw sources
#   make dataset-report   Run dataset_stats.py & (re)generate manifest
#   make dataset-all      dataset-raw + dataset + dataset-report
#
# ──────────────────────────────────────────────────────────────────────

# Auto-detect Python with absolute path (since recipes may cd into subdirs)
PYTHON := $(shell \
  ROOT=$(PWD); \
  if [ -f "$$ROOT/venv/bin/python3" ]; then \
    echo "$$ROOT/venv/bin/python3"; \
  elif [ -f "$$ROOT/.venv/bin/python3" ]; then \
    echo "$$ROOT/.venv/bin/python3"; \
  else \
    echo "python3"; \
  fi \
)

# ── Scripts (full paths from project root) ───────────────────────────
COLLECT_PAYLOADS    := dataset/collect_payloads.py
COLLECT_PORTSWIGGER := dataset/collect_portswigger.py
LABEL_CONTEXTS      := dataset/label_contexts.py
GENERATE_SYNTHETIC  := dataset/generate_synthetic.py
FINALIZE_DATASET    := dataset/finalize_dataset.py
DATASET_STATS       := scripts/dataset_stats.py
DATASET_MANIFEST    := scripts/generate_dataset_manifest.py

# ── Output files (full paths from project root) ──────────────────────
ALL_RAW_CSV       := dataset/processed/all_payloads_raw.csv
PORTSWIGGER_CSV   := dataset/processed/portswigger_payloads.csv
LABELED_CSV       := dataset/processed/payloads_labeled.csv
SYNTHETIC_CSV     := dataset/processed/synthetic_payloads.csv
TRAIN_CSV         := dataset/splits/train.csv
VAL_CSV           := dataset/splits/val.csv
TEST_CSV          := dataset/splits/test.csv
MANIFEST_JSON     := dataset/dataset_manifest.json

# ══════════════════════════════════════════════════════════════════════
#  Targets
# ══════════════════════════════════════════════════════════════════════

.PHONY: help build build-core build-dashboard build-docker \
        train train-ranker train-data evaluate train-all sweep sweep-resume \
        dataset-raw dataset dataset-report dataset-all dataset-clean

help:
	@echo "RedSentinel Makefile"
	@echo ""
	@echo "── Build ──────────────────────────────────────"
	@echo "  make build           Build all (core + dashboard)"
	@echo "  make build-core      Build NestJS core (dist/)"
	@echo "  make build-dashboard Build Next.js dashboard (.next/)"
	@echo "  make build-docker    Build Docker images"
	@echo ""
	@echo "── Train ──────────────────────────────────────"
	@echo "  make train           Train XSS classifier (ai/training/train.py)"
	@echo "  make train-ranker    Train XGBoost ranker (ai/training/train_ranker.py)"
	@echo "  make train-data      Prepare enriched training data from fuzzer samples"
	@echo "  make evaluate        Run model evaluation on clean test split"
	@echo "  make train-all       Full pipeline: train + evaluate"
	@echo "  make sweep           Run Optuna hyperparameter sweep (ai/training/sweep.py)"
	@echo ""
	@echo "── Dataset ────────────────────────────────────"
	@echo "  make dataset-raw     Clone/download raw sources into dataset/raw/"
	@echo "  make dataset         Rebuild all processed CSVs & splits from raw sources"
	@echo "  make dataset-report  Run dataset_stats.py + generate dataset_manifest.json"
	@echo "  make dataset-all     dataset-raw + dataset + dataset-report"
	@echo "  make dataset-clean   Remove dataset/raw/, dataset/processed/, and dataset/splits/"
	@echo ""

# ══════════════════════════════════════════════════════════════════════
#  Build targets
# ══════════════════════════════════════════════════════════════════════

build: build-core build-dashboard
	@echo "Build complete."

build-core:
	@echo "── Building NestJS core ──"
	cd core && npm run build
	@echo ""
	@echo "  ✓ core/dist/ built"
	@echo ""

build-dashboard:
	@echo "── Building Next.js dashboard ──"
	cd dashboard && npm run build
	@echo ""
	@echo "  ✓ dashboard/.next/ built"
	@echo ""

build-docker:
	@echo "── Building Docker images ──"
	docker compose build
	@echo ""
	@echo "  ✓ Docker images built"
	@echo ""

# ══════════════════════════════════════════════════════════════════════
#  Train targets
# ══════════════════════════════════════════════════════════════════════

train:
	@echo "── Training XSS classifier ──"
	cd ai/training && $(PYTHON) train.py
	@echo ""

train-ranker:
	@echo "── Training XGBoost ranker ──"
	cd ai/training && $(PYTHON) train_ranker.py
	@echo ""

train-data:
	@echo "── Preparing enriched training data ──"
	cd ai/training && $(PYTHON) prepare_enriched_training_data.py
	@echo ""

evaluate:
	@echo "── Running model evaluation ──"
	cd ai/training && $(PYTHON) evaluate.py
	@echo ""

# Note: 'train-data' (prepare_enriched_training_data.py) populated the old
# splits_from_ranker/ directory, which is no longer used. Training now
# uses the 60K dataset in dataset/splits/ (synthetic + scraped, properly labeled).
# Run 'make dataset' first to ensure dataset/splits/ exists.
train-all: train evaluate
	@echo "Full ML pipeline complete."
	@echo ""

sweep:
	@echo "── Running Optuna hyperparameter sweep ──"
	cd ai/training && $(PYTHON) sweep.py
	@echo ""

sweep-resume:
	@echo "── Resuming latest Optuna sweep ──"
	cd ai/training && $(PYTHON) sweep.py --study redsentinel_xss_sweep
	@echo ""

# ══════════════════════════════════════════════════════════════════════
#  Dataset targets
# ══════════════════════════════════════════════════════════════════════

# ── dataset-raw: auto-clone/download raw sources ──────────────────────
# Idempotent — skips repos/dirs that already exist.
# Uses shallow clones (--depth 1) to minimise download size.

dataset-raw:
	@mkdir -p dataset/raw
	@echo "── Checking raw sources ──"
	@if [ -d "dataset/raw/AwesomeXSS/.git" ]; then \
		echo "  ✓ AwesomeXSS already cloned"; \
	else \
		echo "  … Cloning AwesomeXSS..."; \
		cd dataset/raw && git clone --depth 1 https://github.com/s0md3v/AwesomeXSS; \
	fi
	@if [ -d "dataset/raw/PayloadsAllTheThings/.git" ]; then \
		echo "  ✓ PayloadsAllTheThings already cloned"; \
	else \
		echo "  … Cloning PayloadsAllTheThings..."; \
		cd dataset/raw && git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings; \
	fi
	@if [ -d "dataset/raw/XSSGAI/.git" ]; then \
		echo "  ✓ XSSGAI already cloned"; \
	else \
		echo "  … Cloning XSSGAI..."; \
		cd dataset/raw && git clone --depth 1 https://github.com/AnonKryptiQuz/XSSGAI; \
	fi
	@if [ -f "dataset/raw/portswigger_raw.html" ]; then \
		echo "  ✓ PortSwigger cheat-sheet already downloaded"; \
	else \
		echo "  … Downloading PortSwigger cheat-sheet..."; \
		curl -sfL https://portswigger.net/web-security/cross-site-scripting/cheat-sheet \
		  -o dataset/raw/portswigger_raw.html; \
	fi
	@echo ""

# ── Dataset pipeline ─────────────────────────────────────────────────
# Each step depends on the previous one's output.
# NOTE: Scripts under dataset/ use relative paths (e.g., "processed/foo.csv")
# so they must run with dataset/ as the working directory.

$(ALL_RAW_CSV): $(COLLECT_PAYLOADS)
	@echo "── Step 1: Collect raw payloads ──"
	cd dataset && $(PYTHON) collect_payloads.py
	@echo ""

$(PORTSWIGGER_CSV): $(COLLECT_PORTSWIGGER)
	@echo "── Step 2: Collect PortSwigger payloads ──"
	@if [ -f dataset/raw/portswigger_raw.html ]; then \
		cd dataset && $(PYTHON) collect_portswigger.py ../dataset/raw/portswigger_raw.html; \
	else \
		echo "  [SKIP] dataset/raw/portswigger_raw.html not found"; \
	fi
	@echo ""

$(LABELED_CSV): $(LABEL_CONTEXTS) $(ALL_RAW_CSV)
	@echo "── Step 3: Label contexts ──"
	cd dataset && $(PYTHON) label_contexts.py
	@echo ""

$(SYNTHETIC_CSV): $(GENERATE_SYNTHETIC) $(LABELED_CSV)
	@echo "── Step 4: Generate synthetic payloads ──"
	cd dataset && $(PYTHON) generate_synthetic.py
	@echo ""

$(TRAIN_CSV) $(VAL_CSV) $(TEST_CSV): $(FINALIZE_DATASET) $(LABELED_CSV) $(SYNTHETIC_CSV)
	@echo "── Step 5: Finalize dataset & split ──"
	cd dataset && $(PYTHON) finalize_dataset.py
	@echo ""
	@echo "Dataset rebuild complete."
	@echo "  Train: $(TRAIN_CSV)"
	@echo "  Val:   $(VAL_CSV)"
	@echo "  Test:  $(TEST_CSV)"

dataset: dataset-raw $(TRAIN_CSV) $(VAL_CSV) $(TEST_CSV)
	@echo ""

# ── Dataset report ───────────────────────────────────────────────────
dataset-report: $(MANIFEST_JSON)
	@echo "── Generating dataset statistics ──"
	$(PYTHON) $(DATASET_STATS)
	@echo ""
	@echo "Report files:"
	@echo "  $(MANIFEST_JSON)"
	@echo ""

$(MANIFEST_JSON): $(DATASET_MANIFEST) $(DATASET_STATS) $(TRAIN_CSV)
	@echo "── Generating dataset manifest ──"
	$(PYTHON) $(DATASET_MANIFEST)
	@echo ""

# ── Combined ─────────────────────────────────────────────────────────
dataset-all: dataset dataset-report
	@echo "Done."

# ── Clean generated data ─────────────────────────────────────────────
dataset-clean:
	@echo "── Cleaning generated dataset directories ──"
	@if [ -d dataset/raw ]; then rm -rf dataset/raw && echo "  ✓ dataset/raw/ removed"; else echo "  - dataset/raw/ (already clean)"; fi
	@if [ -d dataset/processed ]; then rm -rf dataset/processed && echo "  ✓ dataset/processed/ removed"; else echo "  - dataset/processed/ (already clean)"; fi
	@if [ -d dataset/splits ]; then rm -rf dataset/splits && echo "  ✓ dataset/splits/ removed"; else echo "  - dataset/splits/ (already clean)"; fi
	@rm -rf dataset/__pycache__ dataset/*.egg-info 2>/dev/null || true
	@echo ""
	@echo "Run 'make dataset' to rebuild from scratch."
	@echo ""
