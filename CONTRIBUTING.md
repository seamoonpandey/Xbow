# Contributing

Keep changes small, intentional, and aligned with the service boundaries in
`docs/REPOSITORY_GUIDE.md`.

## Before You Start

```bash
git status --short
```

Do not overwrite unrelated local changes. If generated reports, scanner logs,
or model outputs appear, check `.gitignore` before adding them.

## Local Checks

For backend changes:

```bash
cd core
npm test
npm run test:e2e
npm run build
```

For dashboard changes:

```bash
cd dashboard
npm run lint
npm run build
```

For Python module changes:

```bash
pytest tests/modules -v
pytest tests/ -v
```

For setup/script changes:

```bash
bash -n setup.sh start.sh stop.sh coverage.sh scripts/e2e-smoke.sh
```

## Documentation

Update docs in the same change when behavior, ports, dependencies, artifacts,
or service ownership changes. Root `README.md`, `RUN.md`, and
`docs/REPOSITORY_GUIDE.md` are the first places future maintainers will look.
