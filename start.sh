#!/usr/bin/env bash
# ── Red Sentinel — tmux launcher ─────────────────────────────
# Starts all services in a single tmux session with labeled windows.
#
#   Window 0 "infra"     : Redis + Postgres health check
#   Window 1 "python"    : context :5001 | payload-gen :5002 | fuzzer :5003
#   Window 2 "core"      : NestJS API :3000
#   Window 3 "dashboard" : Next.js   :8080
#   Window 4 "exploit"   : Vulnerable test site :9090
#   Window 5 "shell"     : Free terminal with cheat-sheet
#
# Usage:  ./start.sh          (starts & attaches)
#         ./start.sh --detach (starts in background)
# ──────────────────────────────────────────────────────────────
set -euo pipefail

SESSION="rs"
ROOT="$(cd "$(dirname "$0")" && pwd)"
DETACH=false
[[ "${1:-}" == "--detach" || "${1:-}" == "-d" ]] && DETACH=true

# ── Pre-flight checks ────────────────────────────────────────
for cmd in tmux redis-server node python3; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "✗ Required command '$cmd' not found. Install it first." >&2
    exit 1
  fi
done

# ── Kill previous session ────────────────────────────────────
tmux kill-session -t "$SESSION" 2>/dev/null || true
sleep 0.3

# ── Env vars for native (non-Docker) mode ────────────────────
ENV_COMMON=(
  "REDIS_HOST=localhost"
  "REDIS_PORT=6379"
  "CONTEXT_URL=http://localhost:5001"
  "PAYLOAD_GEN_URL=http://localhost:5002"
  "FUZZER_URL=http://localhost:5003"
  "DATABASE_URL=postgresql://rs:rs@localhost:5432/redsentinel"
  "POSTGRES_USER=rs"
  "POSTGRES_PASSWORD=rs"
  "POSTGRES_DB=redsentinel"
  "NODE_ENV=development"
)

# Build an export string to inject into every pane
EXPORT_LINE=""
for ev in "${ENV_COMMON[@]}"; do
  EXPORT_LINE+="export $ev; "
done

# ══════════════════════════════════════════════════════════════
#  Window 0 — infra  (Redis top / Postgres bottom)
# ══════════════════════════════════════════════════════════════
tmux new-session -d -s "$SESSION" -n "infra" -c "$ROOT" -x 220 -y 50

tmux send-keys -t "$SESSION:infra" \
  "printf '\\033[1;36m── Redis ──\\033[0m\\n'; redis-server --daemonize no --loglevel notice" C-m

tmux split-window -v -t "$SESSION:infra" -c "$ROOT" -p 30
tmux send-keys -t "$SESSION:infra.1" \
  "printf '\\033[1;36m── Postgres ──\\033[0m\\n'; \
   pg_isready -h localhost -q && echo 'Postgres is already running' || \
   (sudo pg_ctlcluster 14 main start 2>/dev/null || sudo systemctl start postgresql 2>/dev/null || echo 'Start postgres manually'); \
   echo 'Done.'; exec bash" C-m

# ══════════════════════════════════════════════════════════════
#  Window 1 — python  (3 vertical panes)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "python" -c "$ROOT/modules/context-module"

# Pane 0 — Context module :5001
tmux send-keys -t "$SESSION:python.0" \
  "printf '\\033[1;33m── Context Module :5001 ──\\033[0m\\n'; \
   $EXPORT_LINE \
   cd $ROOT/modules/context-module && python3 app.py" C-m

# Pane 1 — Payload-gen :5002
tmux split-window -v -t "$SESSION:python" -c "$ROOT/modules/payload-gen-module"
tmux send-keys -t "$SESSION:python.1" \
  "printf '\\033[1;33m── Payload-Gen :5002 ──\\033[0m\\n'; \
   $EXPORT_LINE \
   cd $ROOT/modules/payload-gen-module && python3 app.py" C-m

# Pane 2 — Fuzzer :5003
tmux split-window -v -t "$SESSION:python" -c "$ROOT/modules/fuzzer-module"
tmux send-keys -t "$SESSION:python.2" \
  "printf '\\033[1;33m── Fuzzer Module :5003 ──\\033[0m\\n'; \
   $EXPORT_LINE \
   cd $ROOT/modules/fuzzer-module && python3 app.py" C-m

tmux select-layout -t "$SESSION:python" even-vertical

# ══════════════════════════════════════════════════════════════
#  Window 2 — core  (NestJS :3000)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "core" -c "$ROOT/core"
tmux send-keys -t "$SESSION:core" \
  "printf '\\033[1;32m── NestJS Core API :3000 ──\\033[0m\\n'; \
   $EXPORT_LINE \
   export PORT=3000; \
   npm run start:dev" C-m

# ══════════════════════════════════════════════════════════════
#  Window 3 — dashboard  (Next.js :8080)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "dashboard" -c "$ROOT/dashboard"
tmux send-keys -t "$SESSION:dashboard" \
  "printf '\\033[1;35m── Dashboard (Next.js) :8080 ──\\033[0m\\n'; \
   export NEXT_PUBLIC_API_URL=http://localhost:3000; \
   npx next dev -p 8080" C-m

# ══════════════════════════════════════════════════════════════
#  Window 4 — exploit  (Vulnerable test site :9090)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "exploit" -c "$ROOT/exploitable"
tmux send-keys -t "$SESSION:exploit" \
  "printf '\\033[1;31m── Exploitable Test Site :9090 ──\\033[0m\\n'; \
   python3 app.py" C-m

# ══════════════════════════════════════════════════════════════
#  Window 5 — shell  (free terminal)
# ══════════════════════════════════════════════════════════════
tmux new-window -t "$SESSION" -n "shell" -c "$ROOT"
tmux send-keys -t "$SESSION:shell" "$EXPORT_LINE" C-m
tmux send-keys -t "$SESSION:shell" "clear" C-m
tmux send-keys -t "$SESSION:shell" "cat <<'EOF'

  ╔══════════════════════════════════════════════════════╗
  ║              Red Sentinel — Running                  ║
  ╠══════════════════════════════════════════════════════╣
  ║  Redis          localhost:6379                       ║
  ║  Postgres        localhost:5432                      ║
  ║  Context API     http://localhost:5001               ║
  ║  Payload-Gen     http://localhost:5002               ║
  ║  Fuzzer          http://localhost:5003               ║
  ║  Core API        http://localhost:3000               ║
  ║  Dashboard       http://localhost:8080               ║
  ║  Vuln Test Site  http://localhost:9090               ║
  ╠══════════════════════════════════════════════════════╣
  ║  Swagger Docs    http://localhost:3000/docs          ║
  ╠══════════════════════════════════════════════════════╣
  ║  tmux shortcuts:                                     ║
  ║    Ctrl+B n/p   → next / prev window                 ║
  ║    Ctrl+B 0-5   → jump to window                     ║
  ║    Ctrl+B d     → detach (services keep running)     ║
  ║    Ctrl+B o     → switch pane (in python window)     ║
  ╚══════════════════════════════════════════════════════╝

  Quick scan:
    curl -X POST http://localhost:3000/scan \\
      -H 'Content-Type: application/json' \\
      -d '{\"url\":\"http://localhost:9090\"}'

EOF" C-m

# ── Focus on shell window and attach ─────────────────────────
tmux select-window -t "$SESSION:shell"

if $DETACH; then
  echo "Red Sentinel started in tmux session '$SESSION' (detached)."
  echo "Attach with:  tmux attach -t $SESSION"
else
  exec tmux attach -t "$SESSION"
fi
