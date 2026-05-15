# RedSentinel Core

NestJS orchestration service for scans, queue processing, user auth, crawler
coordination, report generation, health checks, and WebSocket progress events.

## Runtime

- Node.js 22+
- NestJS 11
- PostgreSQL via TypeORM migrations
- Redis / BullMQ
- Socket.io WebSocket gateway
- Puppeteer/Chromium for PDF reports

## Local Development

From the repository root, install dependencies once:

```bash
cd core
npm install
```

Run with local Redis/PostgreSQL and Python modules already started:

```bash
DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel npm run start:dev
```

The API listens on `http://localhost:3000`; Swagger is mounted at
`http://localhost:3000/docs`.

## Structure

```text
src/scan/             Scan API, service, gateway, DTOs, entities
src/queue/            BullMQ producer and processor
src/crawler/          Target crawl and DOM/WAF analysis
src/modules-bridge/   HTTP clients for Python microservices
src/report/           HTML, JSON, and PDF report generation
src/userauth/         User/JWT auth, cookies, WebSocket auth
src/auth/             API-key guard for machine clients
src/scanner-log/      Scanner log retrieval
src/health/           Aggregated health endpoint
src/common/           Shared interfaces, exceptions, utilities
src/migrations/       TypeORM migrations
test/                 E2E and integration tests
```

## Checks

```bash
npm test
npm run test:e2e
npm run build
```

## Artifacts

Generated reports live under `reports/` at runtime and are ignored by Git.
Example reports belong in `example_reports/` only when they are intentional
fixtures for documentation or demos.
