# RedSentinel Dashboard

Next.js dashboard for starting scans, watching live progress, reviewing
findings, downloading reports, and inspecting scanner logs.

## Runtime

- Node.js 22+
- Next.js 16 / React 19
- Tailwind CSS 4
- Socket.io client

## Local Development

From the repository root, install dependencies once:

```bash
cd dashboard
npm install
```

Run the dashboard on the project-standard port:

```bash
NEXT_PUBLIC_API_URL=http://localhost:3000 npm run dev -- --port 8080
```

Open `http://localhost:8080`.

## API Routing

The dashboard calls relative `/api/*` paths. `next.config.ts` rewrites those
requests to `NEXT_PUBLIC_API_URL`, which should point at the NestJS core API.

WebSocket connections default to `ws://localhost:3000` in development. Set
`NEXT_PUBLIC_WS_URL` only when the socket endpoint differs from the core API
host.

## Structure

```text
app/                  App Router pages
app/scan/[id]/        Live scan detail view
components/           Reusable dashboard UI
context/              Auth context
hooks/                Socket and client-side hooks
lib/                  API client and shared TypeScript types
public/               Static assets
```

## Checks

```bash
npm run lint
npm run build
```
