# ── RedSentinel Dataset — Makefile ─────────────────────────────────
#
# Reproducible dataset pipeline.  All targets run from project root.
#
# Usage:
#   make dataset          Rebuild processed CSVs & splits from raw sources
#   make dataset-report   Run dataset_stats.py & (re)generate manifest
#   make dataset-all      Both of the above
#
# The raw source directories under dataset/raw/ must exist first
# (gitignored — see dataset/README.md for download instructions).
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
        train train-ranker train-data evaluate train-all \
        dataset dataset-report dataset-all

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
	@echo "  make train-all       Full pipeline: train-data + train + evaluate"
	@echo ""
	@echo "── Dataset ────────────────────────────────────"
	@echo "  make dataset         Rebuild all processed CSVs & splits from raw sources"
	@echo "  make dataset-report  Run dataset_stats.py + generate dataset_manifest.json"
	@echo "  make dataset-all     Both of the above"
	@echo ""
	@echo "Note: dataset/raw/ must exist (see dataset/README.md for download)"
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

train-all: train-data train evaluate
	@echo "Full ML pipeline complete."
	@echo ""

# ══════════════════════════════════════════════════════════════════════
#  Dataset targets (existing)
# ══════════════════════════════════════════════════════════════════════

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

dataset: $(TRAIN_CSV) $(VAL_CSV) $(TEST_CSV)
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
