# Changelog

This directory tracks significant optimizations, bug fixes, and behavioral
changes made to the scanner pipeline. Each entry is a dated file documenting
the research, attempted approaches, and final solution.

Entries are ordered chronologically — read them in sequence to understand how
the scanner evolved.

## Entries

| Date       | Title                                                             | File |
|------------|-------------------------------------------------------------------|------|
| 2026-03-13 | `__fragment__` Context Fix & Browser Verifier Timing Optimization | [2026-03-13-fragment-context-and-browser-verifier.md](2026-03-13-fragment-context-and-browser-verifier.md) |
| 2026-03-13 | Research: Extending to `postMessage` & `localStorage`               | [2026-03-13-research-postmessage-localstorage.md](2026-03-13-research-postmessage-localstorage.md) |
| 2026-05-17 | Dataset Reproducibility Pipeline (Makefile, Manifest, Extended Stats) | [2026-05-17-dataset-reproducibility.md](2026-05-17-dataset-reproducibility.md) |

## Scope

Changelog entries cover:

- **Scanner accuracy** — false positives, false negatives, missed vulns
- **Performance** — timing, throughput, timeout avoidance
- **Coverage** — new vuln types or injection points discovered
- **Infrastructure** — service reliability, debugging, logging

For AI model or dataset changes, see `docs/ML_GUIDE.md`.
For architecture changes, see `docs/ARCHITECTURE.md`.
For detailed bug investigations, see `docs/archive/problems/`.
