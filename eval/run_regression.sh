#!/usr/bin/env bash
# ===========================================================================
# eval/run_regression.sh — CI-Friendly Regression Check Wrapper
#
# Runs the evaluation pipeline then immediately checks results against the
# golden baseline. Exits 0 on pass, 1 on regression.
#
# Usage:
#   ./eval/run_regression.sh                         # full eval + regression
#   ./eval/run_regression.sh --manifest reflected    # single manifest only
#   ./eval/run_regression.sh --skip-eval <run_id>    # check existing run
#   ./eval/run_regression.sh --generate-baseline     # generate baseline from
#                                                      a known-good run
# ===========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_ID="${RUN_ID:-}"  # optional override

echo "=============================================="
echo "  Red Sentinel — Regression Check"
echo "=============================================="
echo ""

# ── Parse args ──────────────────────────────────────────────
MANIFEST_FILTER=""
SKIP_EVAL=false
GEN_BASELINE=false
EVAL_EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest)
            MANIFEST_FILTER="$2"
            shift 2
            ;;
        --skip-eval)
            SKIP_EVAL=true
            RUN_ID="${2:-}"
            shift $(( $# > 1 ? 2 : 1 ))
            ;;
        --generate-baseline)
            GEN_BASELINE=true
            shift
            ;;
        *)
            EVAL_EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# ── Generate baseline mode ─────────────────────────────────
if $GEN_BASELINE; then
    # If a run_id was provided, use it, otherwise run eval first
    if [[ -n "${RUN_ID:-}" ]]; then
        echo "Generating baseline from existing run: $RUN_ID"
    else
        echo "Running full evaluation for baseline..."
        cd "$PROJECT_ROOT"
        python3 eval/run.py --skip-portswigger "${EVAL_EXTRA_ARGS[@]}"
    fi

    cd "$PROJECT_ROOT"
    python3 eval/analysis/regression.py "${RUN_ID:-}" --generate-manifest
    echo ""
    echo "✅  Baseline generated at: eval/regression_manifest.json"
    echo "    Commit this file to version control."
    exit 0
fi

# ── Run evaluation (unless --skip-eval) ─────────────────────
if $SKIP_EVAL; then
    if [[ -z "${RUN_ID:-}" ]]; then
        echo "⚠️  --skip-eval requires a run_id argument"
        echo "   Usage: ./eval/run_regression.sh --skip-eval <run_id>"
        exit 1
    fi
    echo "  Skipping evaluation, checking run: $RUN_ID"
else
    cd "$PROJECT_ROOT"
    EVAL_CMD=(python3 eval/run.py --skip-portswigger)
    if [[ -n "$MANIFEST_FILTER" ]]; then
        EVAL_CMD+=(--manifest "$MANIFEST_FILTER")
    fi
    EVAL_CMD+=("${EVAL_EXTRA_ARGS[@]}")

    echo "  Running: ${EVAL_CMD[*]}"
    echo ""
    if ! "${EVAL_CMD[@]}"; then
        echo ""
        echo "❌  Evaluation pipeline failed. Aborting regression check."
        exit 1
    fi
    echo ""
fi

# ── Run regression check ────────────────────────────────────
cd "$PROJECT_ROOT"
echo "  Running regression check..."
echo ""

if ! python3 eval/analysis/regression.py "${RUN_ID:-}" --json > /tmp/regression_result.json 2>&1; then
    # Regression failed — print details
    echo "=============================================="
    echo "  ❌ REGRESSION DETECTED"
    echo "=============================================="
    python3 -c "
import json
d = json.load(open('/tmp/regression_result.json'))
print(f\"Checks: {d['summary']['passed']} passed, {d['summary']['failed']} failed\")
for c in d.get('metric_checks', []) + d.get('endpoint_checks', []):
    if not c['passed']:
        print(f\"  ❌ [{c['category']}] {c['name']}: {c['message']}\")
"
    echo ""
    echo "Full results: /tmp/regression_result.json"
    exit 1
fi

# Regression passed
echo "=============================================="
python3 -c "
import json
d = json.load(open('/tmp/regression_result.json'))
print(f'  ✅ ALL CHECKS PASSED ({d[\"summary\"][\"passed\"]} checks)')
"
echo "=============================================="
exit 0
