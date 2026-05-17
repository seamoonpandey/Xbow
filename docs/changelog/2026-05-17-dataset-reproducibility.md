# Dataset Reproducibility Pipeline

**Date:** 2026-05-17
**Affects:** `scripts/dataset_stats.py`, `scripts/generate_dataset_manifest.py`, `Makefile`, `dataset/README.md`

---

## Summary

Added a reproducible dataset pipeline with three major additions:

1. **Makefile** (`Makefile`) — Two automation targets:
   - `make dataset` — Rebuilds all processed CSVs and train/val/test splits from raw sources (steps 1–5 of the pipeline)
   - `make dataset-report` — Runs `scripts/dataset_stats.py` and regenerates `dataset/dataset_manifest.json`
   - `make dataset-all` — Both of the above

2. **Dataset Manifest Generator** (`scripts/generate_dataset_manifest.py`) — Writes `dataset/dataset_manifest.json` containing:
   - SHA-256 checksums for all 13 processed/split/ranker artifacts
   - Row counts for every CSV/JSONL file in the pipeline
   - Source repo URLs and commit SHAs (when raw clones are present locally)
   - Git commit SHAs for all 9 pipeline scripts
   - Pipeline execution order

3. **Extended Dataset Statistics** (`scripts/dataset_stats.py`) — Three new sections added to the existing 9-section report:
   - **Section 7** (Payload-Family Balance) — Dominant XSS patterns (`<script>`, `onerror=`, `eval()`, etc.) with per-family counts and top-level categorization (tag_and_handler, tag_only, handler_only, js_uri, template, dom_sink, func_call, other)
   - **Section 8** (Encoding & Obfuscation Categories) — 12 encoding types (unicode_escape, html_entity, url_encoding, double_url_encoding, mixed_case, whitespace_obfuscation, etc.) with multi-encoding depth statistics
   - **Section 12** (Real-World Application Coverage Analysis) — Maps payload patterns to 14 exploitable sink types with endpoint associations, identifies undercovered sink types, documents specialized endpoint needs, cross-references 8,976 browser-verified ranker samples per context, and provides overall coverage strength assessment

---

## Motivation

Previously, dataset size claims ("approximately 59K+") had no reproducible backing. The CSV pipeline was manual and undocumented. The new pipeline makes every step auditable:

- `make dataset` guarantees bit-identical rebuilds from raw sources
- `dataset_manifest.json` proves artifact integrity via SHA-256
- `dataset_stats.py` Section 12 answers the question "how many payloads actually map to real vulnerable app endpoints?"

---

## Behavioral Changes

| Area | Before | After |
| --- | --- | --- |
| Dataset rebuild | Manual script-by-script | Single `make dataset` |
| Dataset verification | None | `make dataset-report` produces stats + manifest |
| Payload-family analysis | Not available | Section 7 in stats output |
| Encoding analysis | Not available | Section 8 in stats output |
| Coverage analysis | Not available | Section 12 in stats output |
| Artifact integrity | Untracked | SHA-256 checksums in manifest |
| Documentation | No pipeline docs | Full pipeline description in `dataset/README.md` |

---

## Files Affected

- `Makefile` — New file: automation targets
- `scripts/dataset_stats.py` — Extended with sections 7, 8, 12
- `scripts/generate_dataset_manifest.py` — New file: manifest generator
- `dataset/dataset_manifest.json` — New file: generated output
- `dataset/README.md` — Updated with pipeline, manifest, and coverage docs
