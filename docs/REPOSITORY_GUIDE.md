# Repository Guide

This guide defines what belongs in Git, where new work should live, and which
documents are authoritative.

## Source of Truth

- `README.md` is the project entry point: architecture summary, quick start,
  API surface, testing, environment variables, and top-level structure.
- `RUN.md` is the step-by-step local setup/run guide.
- `docs/ARCHITECTURE.md` holds deeper architecture and design rationale.
- `docs/ML_GUIDE.md` is the canonical short guide for model/data ownership.
- Service-local READMEs explain how to work inside `core/`, `dashboard/`,
  `dataset/`, `exploitable/`, and `tools/`.

When these documents disagree, update the narrower document and the source of
truth in the same change.

## Directory Ownership

```text
core/          NestJS API, queue, crawler, auth, reports, migrations
dashboard/     Next.js UI and browser-facing API/socket client
modules/       Python FastAPI microservices and shared schemas
dataset/       Curated and processed XSS payload data
model/         Tokenizer, ranker model, small metrics, checkpoint metadata
ai/            Training code for context/severity models
tools/         Offline inference, inspection, calibration, export utilities
exploitable/   Local vulnerable target app for scanner validation
scripts/       Project-level automation
tests/         Cross-module Python integration/regression tests
docs/          Active guides plus archived historical notes
outputs/       Local generated tool outputs; ignored except `.gitkeep`
```

## Artifact Policy

Tracked:

- Source code, tests, migrations, templates, service READMEs, and docs.
- Curated/processed datasets that are small enough for normal Git review.
- Small model metadata such as metrics and tokenizer files.
- Intentional fixtures, such as curated example reports.

Ignored:

- `.env`, `.env.*`, local virtual environments, `node_modules`, `.next`, and
  build output.
- Raw cloned datasets under `dataset/raw/`.
- Large model checkpoints such as `model/checkpoints/*.pt`.
- Runtime reports and scanner logs under `reports/`, `core/reports/`, and
  `core/scanner-logs/`.
- Generated inference outputs under `outputs/`.
- Redis dumps, setup logs, coverage reports, and local cache directories.

## Dependency Policy

- Node services keep separate lockfiles in `core/` and `dashboard/`.
- Root `requirements.txt` is the local all-in-one Python environment used by
  `setup.sh`, `RUN.md`, and `start.sh`.
- Per-service Python `requirements.txt` files are the Docker build inputs for
  their microservices.
- Tool-specific dependencies live in `tools/requirements.txt` and
  `tools/inference/requirements.txt`.

If a dependency is needed in both Docker and local development, update both the
service requirements and the root requirements in the same change.

## Naming Notes

- `core/src/userauth/` is user/JWT/cookie auth for dashboard sessions and
  WebSocket authentication.
- `core/src/auth/` is API-key auth for machine clients. Keep this split clear
  in imports and docs.
