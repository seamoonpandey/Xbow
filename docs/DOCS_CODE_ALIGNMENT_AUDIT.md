# Documentation / Code Alignment Audit

Date: 2026-05-16

This audit records the documentation/code alignment work and the follow-up schema cleanup. Application code, DTOs, Pydantic schemas, Docker Compose, and tests remain the source of truth.

## Current documentation ownership map

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

## Alignment fixes applied

| Area | Source of truth | Fix applied | Status |
|---|---|---|---|
| Core scan API | `core/src/scan/scan.controller.ts` | Canonical docs now list the implemented scan, audit, cancel, delete, list, and report-pointer routes with their actual behavior. | Done |
| Report routes | `core/src/scan/scan.controller.ts`, `core/src/report/report.controller.ts` | Docs distinguish `/scan/:id/report` as a pointer-only route and `/reports/:scanId/download` as the file-download route. | Done |
| Core scan options | `core/src/scan/dto/create-scan.dto.ts` | Docs use camelCase Core option names: `maxParams`, `verifyExecution`, `wafBypass`, `maxPayloadsPerParam`, `reportFormat`, `singlePage`, and `auth`. | Done |
| Python schema names | `modules/shared/schemas.py`, FastAPI apps | Docs keep snake_case only for Python service payloads, such as `max_payloads`, `verify_execution`, `stored_mode`, `display_url`, and `form_fields`. | Done |
| Python context API | `modules/context-module/app.py` | Context contract is documented as `POST /analyze` returning a bare parameter map. Local `AnalyzeRequest` now matches shared fields and accepts `cookie_header`. | Done |
| Context authenticated probing | `core/src/modules-bridge/context-client.service.ts`, `modules/context-module/app.py`, `modules/context-module/probe_injector.py`, `modules/context-module/char_fuzzer.py` | Core forwards `cookie_header`; context module declares it and passes it into probe and character-fuzz HTTP requests. | Done |
| Python payload-gen API | `modules/payload-gen-module/app.py`, `modules/shared/schemas.py` | Docs document `/generate`, `/health`, `/ranker/info`, and the `max_payloads` request field. | Done |
| Payload ranking | `modules/payload-gen-module/app.py` | Docs say XGBoost is used only when the ranker model loads; otherwise heuristic ranking is used. | Done |
| Python fuzzer API | `modules/fuzzer-module/app.py`, `modules/shared/schemas.py` | Docs document `/test`, `/health`, and `/training/stats`; `/fuzz` is not documented. Shared `FuzzRequest` now declares `auth_cookie_header` and `auth_storage_state`. | Done |
| Fuzzer auth wording | `core/src/modules-bridge/fuzzer-client.service.ts` | TypeScript comments no longer claim browser-level storage-state auth is active. Storage state is forwarded as optional schema-compatible future input. | Done |
| Fuzzer HTTP sender | `modules/fuzzer-module/http_sender.py` | HTTP helper functions now accept optional `cookie_header` and build request headers with cookies when supplied. | Partially wired |
| Health checks | `core/src/health/*`, Python FastAPI apps | Docs describe Core aggregate health and Python health fields. | Done |
| Runtime artifacts | `docker-compose.yml` | Docs list mounted `model/`, `model/ranker/`, `dataset/splits/`, `training_data`, `reports`, and PostgreSQL volumes. | Done |
| Severity scoring | `core/src/common/utils/severity-scorer.ts` | Docs describe the implemented rule-based scorer, thresholds, and `HASH_SOURCE_MEDIUM_CAP`; CVSS/ALE claims were removed. | Done |
| Dataset size/sources | `dataset/README.md`, dataset scripts/artifacts | Canonical docs use “approximately 59K+” unless an exact tracked artifact proves otherwise; source list is consistent. | Done |
| Context/finding taxonomy | Context module, fuzzer module, shared schemas, dataset docs | Docs separate runtime reflection contexts, training/evaluation labels, and vulnerability/finding labels. | Done |
| Testing claims | `core/package.json`, test configs | Docs list available test commands without claiming pass counts. | Done |
| Documentation hierarchy | `docs/README.md`, `docs/REPOSITORY_GUIDE.md` | Docs now define a single ownership map and mark `docs/archive/` as historical. | Done |

## Redundancy and micro-detail cleanup

- `README.md` is now an entry point and summary, not a duplicate schema reference.
- `docs/ARCHITECTURE.md` is the detailed API and service-contract source.
- `docs/SCAN_PARAMETERS_GUIDE.md` is the scan option/tuning source.
- `dataset/README.md` owns dataset source/layout details.
- `docs/ML_GUIDE.md` owns model/ranker/fallback and taxonomy guidance.
- `RUN.md` remains operational and may repeat executable commands because setup docs need examples.
- `docs/README.md` and `docs/REPOSITORY_GUIDE.md` use matching ownership wording.

## Remaining implementation cleanup notes

1. `modules/fuzzer-module/http_sender.py` now accepts `cookie_header`, and `modules/shared/schemas.py` declares `auth_cookie_header`, but `modules/fuzzer-module/app.py` still needs a small wiring pass to pass `request.auth_cookie_header` into `fetch_url`, `send_payloads`, and `send_stored_payloads`.
2. `auth_storage_state` is declared and forwarded for schema compatibility, but the Python browser verifier does not currently consume Playwright storage state. Do not document browser-level authenticated verification as active until `browser_verifier.py` uses this field.
3. Core still contains both `userauth/` JWT/session auth and `auth/` API-key auth concepts. Docs distinguish them, but a future code cleanup could make the intended public auth model clearer.
4. Report generation supports multiple formats through `ReportController`, while `ScanController.getReport()` returns only a static HTML URL pointer. Docs explain this, but the API could be consolidated later.

## Stale-term checks

Repository searches were run for stale/suspicious terms including:

- `24,000`, `24K`, `59,122`
- `CVSS`, `ALE`
- `/fuzz`
- `max_params`, `verify_execution`, `waf_bypass`, `max_payloads_per_param`, `report_format`
- `HASH_SOURCE_LOW_CAP`
- `download HTML/PDF/JSON`
- `always XGBoost`
- `six classes`, `6 classes`

Canonical docs were updated or qualified. Snake_case names remain only where they accurately describe Python service schemas or bridge payloads.

## Validation performed

- Inspected Core scan/report/health controllers, DTOs, bridge clients, severity scorer, Docker Compose, Python FastAPI apps, shared schemas, and canonical docs.
- Updated canonical documentation to match code behavior.
- Reduced README-level duplication so detailed contracts have a single primary home.
- Tightened canonical-document ownership wording in `docs/README.md` and `docs/REPOSITORY_GUIDE.md`.
- Cleaned several small code/schema inconsistencies around context and fuzzer auth fields.
- Ran GitHub repository searches for stale/suspicious terms through the connected GitHub search tool.
- Tests and markdown lint were not run in this environment. The repository includes test commands, but this audit does not claim passing results.
