# RedSentinel Docs

These documents are the canonical documentation set for the current implementation:

1. `../README.md` — project overview, implemented service/API summary, runtime artifacts, and test commands.
2. `../RUN.md` — full local setup and run guide.
3. `ARCHITECTURE.md` — detailed architecture, API contracts, service responsibilities, report behavior, and scoring model.
4. `REPOSITORY_GUIDE.md` — directory ownership, artifact policy, dependency policy, and documentation ownership.
5. `SCAN_PARAMETERS_GUIDE.md` — scan-tuning behavior for implemented scan options.
6. `ML_GUIDE.md` — concise ML/data/model maintenance guide.
7. `../dataset/README.md` — dataset sources and generated dataset structure.
8. `DOCS_CODE_ALIGNMENT_AUDIT.md` — latest documentation/code alignment audit and fixes applied.

## Source-of-truth order

When documentation and implementation disagree, use this order:

1. Actual application code
2. DTOs, Pydantic schemas, TypeScript interfaces, service clients
3. Docker Compose and runtime configuration
4. Tests and package scripts
5. Current canonical docs
6. Archived docs only as historical reference

## Secondary References

- `evaluation/` — current evaluation reports and generated charts when they support a tracked report.
- `archive/` — historical plans, progress notes, older investigations, and stale deep dives. These files are preserved for context only and are not canonical for current API, schema, architecture, dataset, or ML claims.

## Documentation rule

Keep canonical docs concise and implementation-defensible. Do not claim exact dataset counts, CVSS/ALE scoring, always-on XGBoost ranking, direct report downloads from `/scan/:id/report`, or a single universal six-class taxonomy unless the current code proves it.

If a new document is not part of the main onboarding path, place it under `archive/` or a clearly named subdirectory with a short index.
