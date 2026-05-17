# Documentation / Code Alignment Audit

Date: 2026-05-16

Scope: documentation was checked against the current implementation in Core controllers/DTOs/bridge clients, Python FastAPI apps/shared schemas, Docker Compose, severity scorer, report controller behavior, package scripts, and canonical docs.

## Current documentation ownership map

To reduce redundancy and avoid conflicting claims, each topic has one primary home:

| Topic | Primary canonical home | Secondary references |
|---|---|---|
| Project overview and quick start | `README.md` | `RUN.md` for manual setup |
| Detailed architecture and API contracts | `docs/ARCHITECTURE.md` | `README.md` only summarizes endpoints |
| Local/manual running instructions | `RUN.md` | `README.md` links to it |
| Scan option names, ranges, and tuning | `docs/SCAN_PARAMETERS_GUIDE.md` | `README.md` includes only a minimal example |
| Dataset sources and generated dataset layout | `dataset/README.md` | `docs/ML_GUIDE.md` summarizes sources |
| ML artifacts, model/ranker behavior, fallback rules | `docs/ML_GUIDE.md` | `README.md` and `docs/ARCHITECTURE.md` summarize only |
| Repository ownership and artifact policy | `docs/REPOSITORY_GUIDE.md` | `docs/README.md` lists canonical docs |
| Historical notes and stale investigations | `docs/archive/` | Historical only; not source of truth |

## Audit Table

| Area | Document/file with issue | Existing claim | Code source of truth | Problem | Fix applied | Priority |
|---|---|---|---|---|---|---|
| Core scan API | `README.md`, `docs/ARCHITECTURE.md` | Partial scan endpoint list; missing audit/delete-all/delete-by-id distinctions | `core/src/scan/scan.controller.ts` | Docs did not fully describe implemented scan routes | Added `POST /scan`, `GET /scan/:id`, `GET /scans`, `GET /scan/:id/audit`, `GET /scan/:id/report`, `DELETE /scan/:id`, `DELETE /scans/:id`, and `DELETE /scans` with actual behavior | High |
| Report pointer endpoint | `README.md`, `RUN.md`, `docs/ARCHITECTURE.md`, `docs/SCAN_PARAMETERS_GUIDE.md` | `/scan/:id/report` implied report download in some places | `core/src/scan/scan.controller.ts` | `/scan/:id/report` only returns `{ reportUrl: "/reports/<id>.html" }` | Reworded as pointer-only endpoint and documented report downloads through `/reports/:scanId/download` | High |
| Report controller routes | `README.md`, `RUN.md`, `docs/ARCHITECTURE.md` | Report download/regeneration behavior was incomplete or attached to the wrong endpoint | `core/src/report/report.controller.ts` | Existing docs mixed generated report files with scan pointer endpoint | Added `/reports/:scanId`, `/reports/:scanId/download?format=...`, and `/reports/:scanId/regenerate?formats=...` | High |
| Scan request option naming | `docs/ARCHITECTURE.md`, `RUN.md`, `README.md` | Stale snake_case Core request fields such as `max_params`, `verify_execution`, `waf_bypass`, `max_payloads_per_param`, `report_format` | `core/src/scan/dto/create-scan.dto.ts` | Public Core DTO uses camelCase | Updated examples to `maxParams`, `verifyExecution`, `wafBypass`, `maxPayloadsPerParam`, `reportFormat`; kept snake_case only for Python microservice schemas | High |
| Target-site authentication | `README.md`, `RUN.md`, `docs/ARCHITECTURE.md`, `docs/SCAN_PARAMETERS_GUIDE.md` | Auth behavior not clearly distinguished from API auth | `CreateScanDto.AuthOptionsDto`, `core/src/queue/scan.processor.ts`, bridge clients | Docs could confuse target login with RedSentinel API authentication | Documented `options.auth` fields, login fallback behavior, and distinction from API/JWT auth | High |
| API authentication wording | `README.md`, `RUN.md`, `docs/REPOSITORY_GUIDE.md` | All endpoints described as requiring `x-api-key`/API-key auth | `ScanController` and `ReportController` use `JwtAuthGuard`; `HealthController` is public | Docs overstated API-key use for scan/report routes | Updated docs to describe JWT-guarded scan/report routes and public `/health`; noted API-key components separately where wired | High |
| Python context API | `README.md`, `docs/ARCHITECTURE.md` | Context schema could be read as wrapped response or as shared schema superset | `modules/context-module/app.py`; `modules/shared/schemas.py` | Context app has local model and returns a bare param map | Detailed schema kept in `docs/ARCHITECTURE.md`; README now links there instead of duplicating full schemas | High |
| Python payload-gen API | `README.md`, `docs/ARCHITECTURE.md`, `docs/ML_GUIDE.md` | XGBoost/ranker behavior was too absolute or incomplete | `modules/payload-gen-module/app.py`; `modules/shared/schemas.py` | XGBoost is conditional; `/ranker/info` exists | Documented `/generate`, `/health`, `/ranker/info`, `max_payloads`, and XGBoost-with-heuristic-fallback behavior; full contract lives in `docs/ARCHITECTURE.md` | High |
| Python fuzzer API | `README.md`, `docs/ARCHITECTURE.md` | Fuzzer route naming drift between `/test` and `/fuzz` | `modules/fuzzer-module/app.py`; `modules/shared/schemas.py`; `core/src/modules-bridge/fuzzer-client.service.ts` | Canonical endpoint is `/fuzz`; `/test` remains a legacy alias | Documented `/fuzz`, `/health`, `/training/stats`; noted `/test` compatibility in `docs/ARCHITECTURE.md`; Core bridge calls `/fuzz` | High |
| Health checks | `README.md`, `RUN.md`, `docs/ARCHITECTURE.md` | Health responses were incomplete | `core/src/health/*`, Python `app.py` files | Docs did not show actual response fields | Added Core aggregate health shape and Python service health fields where operationally useful | Medium |
| Docker/runtime artifacts | `README.md`, `RUN.md`, `docs/ARCHITECTURE.md`, `docs/REPOSITORY_GUIDE.md`, `docs/ML_GUIDE.md`, `dataset/README.md` | Mounted artifacts/fallbacks were incomplete | `docker-compose.yml`, Python app startup code | Missing model, ranker, dataset split, reports, and training data mount details | Documented all relevant mounts and fallback behavior; README keeps a compact summary, detailed ownership lives in repository/ML/run docs | Medium |
| Severity scoring | `docs/ARCHITECTURE.md` | Old `HASH_SOURCE_LOW_CAP`; possible impression that CVSS/ALE replaced runtime severity | `core/src/common/utils/severity-scorer.ts`, `core/src/common/utils/risk-calculus.ts` | Runtime severity is rule-based; CVSS-inspired/ALE values are a separate report-layer analytical model | Documented rule-based axes, thresholds, overrides, `HASH_SOURCE_MEDIUM_CAP`, and the separate report-layer risk model | High |
| Dataset size | `README.md`, `docs/ARCHITECTURE.md`, `docs/ML_GUIDE.md`, `dataset/README.md`, `docs/REPOSITORY_GUIDE.md` | Docs used “approximately 59K+” with caveats | `scripts/dataset_stats.py` Section 11, `dataset/dataset_manifest.json` | Exact count (59,122) now proven by reproducible script and tracked manifest | Updated all canonical docs to use exact count **59,122** with reference to `scripts/dataset_stats.py` | Resolved |
| Dataset sources | `README.md`, `docs/ARCHITECTURE.md`, `docs/ML_GUIDE.md`, `dataset/README.md` | Source lists were not consistently repeated | `dataset/README.md` download/source section | Canonical docs should share one source list | Standardized sources: AwesomeXSS, PayloadsAllTheThings, XSSGAI, PortSwigger XSS cheat sheet content | Medium |
| Context taxonomy | `README.md`, `docs/ARCHITECTURE.md`, `docs/ML_GUIDE.md`, `dataset/README.md` | Risk of presenting one six-class taxonomy as universal | Context app, fuzzer app, shared schemas | Runtime reflection contexts, training labels, and vulnerability labels differ | Separated runtime reflection contexts from vulnerability/finding labels and training labels | Medium |
| Testing claims | `README.md`, `docs/ARCHITECTURE.md` | Specific pass/test counts such as unit/e2e totals | `core/package.json`, test folders/configs | Counts should not be claimed unless tests are run now | Removed pass-count claims; documented available test suites and commands only | Medium |
| Documentation hierarchy | `docs/README.md`, `docs/REPOSITORY_GUIDE.md`, `README.md` | Canonical docs and archive status needed stronger wording; README duplicated detailed schemas | Current docs layout | Historical files can conflict with current implementation; duplicated schemas can drift | Added source-of-truth order, marked `docs/archive/` historical/non-canonical, and reduced README to an entry point with links to detailed canonical docs | Medium |
| Micro-level ownership wording | `docs/README.md`, `docs/REPOSITORY_GUIDE.md` | Some descriptions still implied older README responsibilities after redundancy cleanup | Current canonical doc layout | Index/ownership wording could mislead future maintainers about where details belong | Tightened document descriptions so detailed API contracts live in `ARCHITECTURE.md`, scan tuning in `SCAN_PARAMETERS_GUIDE.md`, dataset details in `dataset/README.md`, and README remains the entry point | Medium |

## Redundancy cleanup pass

A second cleanup pass reduced duplication after the initial alignment:

- `README.md` now stays at overview level and links to `docs/ARCHITECTURE.md` for detailed API/microservice schemas.
- `README.md` links to `docs/SCAN_PARAMETERS_GUIDE.md` for scan tuning instead of repeating all target-auth and schema details.
- `RUN.md` remains operational and is allowed to repeat concrete commands because those are needed for setup.
- `docs/ARCHITECTURE.md` remains the detailed implementation/API contract document.
- `docs/SCAN_PARAMETERS_GUIDE.md` remains focused on DTO option names, ranges, and tuning behavior.
- `docs/ML_GUIDE.md` and `dataset/README.md` share consistent dataset/ranker wording, with dataset source detail anchored in `dataset/README.md`.

## Micro-detail cleanup pass

A third pass checked smaller wording and mapping issues after redundancy cleanup:

- `docs/README.md` now describes each canonical doc by its precise current responsibility.
- `docs/REPOSITORY_GUIDE.md` now matches the same ownership model as `docs/README.md`.
- README responsibility wording was narrowed from detailed runtime/API ownership to entry-point and summary ownership.
- Architecture wording remains the single home for detailed Core/Python API contracts.
- Scan-parameters wording remains the single home for DTO option ranges and tuning explanations.
- Dataset and ML docs remain split by source/layout (`dataset/README.md`) versus model/ranker/fallback ownership (`docs/ML_GUIDE.md`).

## New additions since the audit

### Dataset reproducibility pipeline (2026-05-17)

Three new components were added and documented together:
| Area | Document/file with issue | Existing claim | Code source of truth | Problem | Fix applied | Priority |
|---|---|---|---|---|---|---|
| Dataset pipeline automation | `README.md`, `dataset/README.md`, `docs/ML_GUIDE.md`, `docs/REPOSITORY_GUIDE.md` | No Makefile, no manifest, no stats report | `Makefile`, `scripts/dataset_stats.py`, `scripts/generate_dataset_manifest.py` | Pipeline was manual and unverifiable | Added `Makefile` targets, 12-section stats script, manifest generator; documented in `dataset/README.md`, `docs/ML_GUIDE.md`, and changelog | High |
| Coverage analysis | `dataset/README.md`, `docs/ML_GUIDE.md` | No mapping of payloads to real-world endpoints | `scripts/dataset_stats.py` Section 12 | No visibility into what sink types the dataset covers | Added Section 12 with 14 sink types, 5 specialized endpoint notes, browser-verified cross-reference, coverage strength tiers | Medium |
| Dataset integrity | `dataset/README.md`, `docs/REPOSITORY_GUIDE.md` | No checksums or row-count tracking | `scripts/generate_dataset_manifest.py`, `dataset/dataset_manifest.json` | Artifact drift was invisible | Manifest records SHA-256, row counts, source metadata; added to tracked artifacts policy | Medium |

## Remaining code-level inconsistencies to clean up later

1. `modules/shared/schemas.py` defines richer context request fields (`form_method`, `form_fields`, `display_url`) than the local `modules/context-module/app.py` `AnalyzeRequest`, which currently accepts only `url`, `params`, and `waf`.
2. `ContextClientService` can forward `cookie_header`, but the context module local Pydantic request model does not declare it. Pydantic may ignore extra fields depending on defaults; this should be made explicit in code if authenticated context probing is required.
3. Core contains both `userauth/` JWT/session auth and `auth/` API-key auth concepts. Docs now distinguish them, but future code cleanup could make intended public API auth clearer.
4. Report generation supports multiple formats through `ReportController`, while `ScanController.getReport()` returns only a static HTML URL pointer. This is now documented, but the API may be clearer if these surfaces are consolidated later.

## Stale-term search results

Repository searches were run for the requested stale/suspicious terms after documentation edits. Canonical docs were updated or qualified for:

- `24,000`
- `24K`
- `CVSS`
- `ALE`
- `/test` as canonical fuzzer route
- `max_params`
- `verify_execution`
- `waf_bypass`
- `max_payloads_per_param`
- `HASH_SOURCE_LOW_CAP`
- `download HTML/PDF/JSON`
- `always XGBoost`
- `six classes`
- `6 classes`

Snake_case names such as `verify_execution` and `max_payloads` remain accurate where they describe Python microservice schemas or bridge payloads.

## Validation performed

- Inspected Core scan controller, create-scan DTO, report controller, health controller/service, module bridge clients, severity scorer, Docker Compose, Python FastAPI apps, shared schemas, package scripts, and canonical docs.
- Updated canonical documentation to match code behavior.
- Reduced README-level duplication so detailed contracts have a single primary home.
- Tightened canonical-document ownership wording in `docs/README.md` and `docs/REPOSITORY_GUIDE.md`.
- Ran GitHub repository searches for stale/suspicious terms through the connected GitHub search tool.
- Tests and markdown lint were not run in this environment. The repository includes test commands, but this audit does not claim passing results.
