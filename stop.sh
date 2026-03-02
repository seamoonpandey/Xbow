#!/usr/bin/env bash
# ── Red Sentinel — stop all services ─────────────────────────
set -euo pipefail

SESSION="rs"

echo "Stopping Red Sentinel..."

# Kill the tmux session (sends SIGHUP to all panes)
if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
  echo "  ✓ tmux session '$SESSION' killed"
else
  echo "  · no tmux session '$SESSION' found"
fi

# Clean up any orphaned processes on known ports
for port in 5001 5002 5003 3000 8080 9090; do
  pid=$(lsof -ti :"$port" 2>/dev/null || true)
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    echo "  ✓ killed process on :$port (pid $pid)"
  fi
done

echo "Done."
