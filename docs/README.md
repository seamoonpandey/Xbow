# RedSentinel Docs

These documents are the canonical documentation set for the current implementation:

1. `../README.md` — project entry point: concise overview, quick start, implemented endpoint summary, and links to deeper docs.
2. `../RUN.md` — full local setup and run guide with operational commands.
3. `ARCHITECTURE.md` — detailed architecture, Core API reference, Python microservice contracts, report behavior, health behavior, and severity model.
4. `SCAN_PARAMETERS_GUIDE.md` — implemented Core scan option names, ranges, target-site auth options, and tuning behavior.
5. `ML_GUIDE.md` — model/data/ranker ownership, ML fallback behavior, and taxonomy guidance.
6. `../dataset/README.md` — dataset sources, generated dataset layout, dataset runtime use, and raw-source download notes.
7. `REPOSITORY_GUIDE.md` — directory ownership, artifact policy, dependency policy, and documentation hygiene rules.
8. `DOCS_CODE_ALIGNMENT_AUDIT.md` — documentation/code alignment audit, cleanup record, and known remaining code-level inconsistencies.

## Source-of-truth order

When documentation and implementation disagree, use this order:

1. Actual application code
2. DTOs, Pydantic schemas, TypeScript interfaces, service clients
3. Docker Compose and runtime configuration
4. Tests and package scripts
5. Current canonical docs
6. Archived docs only as historical reference

## Secondary References

- `../eval/README.md` — **evaluation results index**: cross-tool comparisons, 47-endpoint full evaluation, multi-target real-world results, and analysis scripts. Start here for all benchmarking data.
- `evaluation/` — legacy evaluation reports and generated charts (superseded by `../eval/`).
- `archive/` — historical plans, progress notes, older investigations, and stale deep dives. These files are preserved for context only and are not canonical for current API, schema, architecture, dataset, or ML claims.

## Documentation rule

Keep canonical docs concise and implementation-defensible. Do not claim exact dataset counts, always-on XGBoost ranking, direct report downloads from `/scan/:id/report`, or a single universal six-class taxonomy unless the current code proves it. Runtime severity is rule-based; CVSS/ALE/expected-loss wording must refer only to the separate report-layer analytical model.

If a new document is not part of the main onboarding path, place it under `archive/` or a clearly named subdirectory with a short index.
