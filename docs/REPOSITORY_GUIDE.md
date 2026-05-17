# Repository Guide

This guide defines what belongs in Git, where new work should live, and which documents are authoritative.

## Source of Truth

When documentation and implementation disagree, use this order:

1. Actual application code
2. DTOs, Pydantic schemas, TypeScript interfaces, service clients
3. Docker Compose and runtime configuration
4. Tests and package scripts
5. Current canonical docs
6. Archived docs only as historical reference

## Canonical Documents

- `README.md` is the project entry point: concise overview, quick start, implemented endpoint summary, and links to deeper docs.
- `RUN.md` is the step-by-step local setup/run guide with operational commands.
- `docs/ARCHITECTURE.md` is the detailed architecture and API-contract source: service responsibilities, Core API, Python microservice contracts, report behavior, health behavior, and severity model.
- `docs/SCAN_PARAMETERS_GUIDE.md` documents scan-tuning options from the implemented Core DTO.
- `docs/ML_GUIDE.md` documents model/data/ranker ownership, fallback behavior, and ML taxonomy guidance.
- `dataset/README.md` documents dataset sources, generated dataset layout, dataset runtime use, and raw-source download notes.
- `docs/DOCS_CODE_ALIGNMENT_AUDIT.md` records documentation/code mismatches, cleanup passes, and known remaining code-level inconsistencies.
- `scripts/dataset_stats.py` is the authoritative source for dataset size claims and diversity analysis.
- `scripts/generate_dataset_manifest.py` produces the reproducible `dataset/dataset_manifest.json`.
- `Makefile` automates the dataset pipeline: `make dataset`, `make dataset-report`, `make dataset-all`.

When canonical docs disagree, update the narrower document and the higher-level source in the same change.

## Directory Ownership

```text
core/          NestJS API, queue, crawler, user/API auth, reports, health, scanner logs, migrations
dashboard/     Next.js UI and browser-facing API/socket client
modules/       Python FastAPI microservices and shared schemas
dataset/       Curated, processed, split, and raw/ignored XSS payload data
model/         Tokenizer, ranker model, small metrics, local checkpoint metadata
ai/            Training code for context/ranking-related models
tools/         Offline inference, inspection, calibration, export utilities
exploitable/   Local vulnerable target app for scanner validation
scripts/       Project-level automation and smoke tests
tests/         Cross-module Python integration/regression tests
docs/          Active guides plus archived historical notes
outputs/       Local generated tool outputs; ignored except `.gitkeep`
```

## Artifact Policy

Tracked:

- Source code, tests, migrations, templates, service READMEs, and canonical docs.
- Curated/processed datasets that are small enough for normal Git review.
- Small model metadata such as metrics, tokenizer files, and ranker metadata when appropriate.
- Intentional fixtures, such as curated example reports.
- The dataset manifest `dataset/dataset_manifest.json` (tracked as the authoritative integrity record).
- Pipeline automation scripts under `scripts/` and the `Makefile`.

Ignored or mounted locally:

- `.env`, `.env.*`, local virtual environments, `node_modules`, `.next`, and build output.
- Raw cloned datasets under `dataset/raw/`.
- Large model checkpoints such as `model/checkpoints/*.pt`.
- Runtime reports and scanner logs under `reports/`, `core/reports/`, and `core/scanner-logs/`.
- Generated inference outputs under `outputs/`.
- Redis dumps, setup logs, coverage reports, and local cache directories.

Docker Compose mounts the current runtime artifact paths explicitly:

- `./model:/app/model:ro`
- `./dataset/splits:/app/dataset/splits:ro`
- `./model/ranker:/app/model/ranker:ro`
- `training_data:/app/training_data`
- `reports:/app/reports`
- `pgdata:/var/lib/postgresql/data`

## Dependency Policy

- Node services keep separate lockfiles in `core/` and `dashboard/`.
- Root `requirements.txt` is the local all-in-one Python environment used by `setup.sh`, `RUN.md`, and `start.sh`.
- Per-service Python `requirements.txt` files are the Docker build inputs for their microservices.
- Tool-specific dependencies live in `tools/requirements.txt` and `tools/inference/requirements.txt` when present.

If a dependency is needed in both Docker and local development, update both the service requirements and the root requirements in the same change.

## Naming Notes

- `core/src/userauth/` is user/JWT/cookie auth for dashboard sessions, guarded scan/report routes, and WebSocket authentication.
- `core/src/auth/` contains API-key auth components for machine-client use where wired. Do not describe all scan routes as API-key guarded unless the controller wiring proves it.
- `options.auth` in `CreateScanDto` is target-site authentication for scanning protected target applications, not RedSentinel API authentication.

## Documentation Hygiene Rules

- Use camelCase scan option names from `CreateScanDto`: `maxParams`, `verifyExecution`, `wafBypass`, `maxPayloadsPerParam`, and `reportFormat`.
- Use Python schema names for microservice contracts: `max_payloads`, `verify_execution`, `stored_mode`, `display_url`, and `form_fields`.
- Document `/fuzz` as the canonical fuzzer route; `/test` is only a legacy compatibility alias.
- Do not claim `/scan/:id/report` downloads HTML/PDF/JSON. It returns a report URL pointer only.
- Runtime severity is rule-based. CVSS-inspired, ALE, and expected-loss values may be documented only as the separate report-layer analytical model implemented in `core/src/common/utils/risk-calculus.ts`.
- Use `HASH_SOURCE_MEDIUM_CAP`, not the stale `HASH_SOURCE_LOW_CAP` name.
- Use the exact dataset size from `scripts/dataset_stats.py` Section 11 (currently **59,122**). The script is the authoritative source.
- Mark `docs/archive/` as historical whenever referencing it.
