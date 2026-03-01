#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# coverage.sh — unified coverage runner for RedSentinel
# generates html + lcov reports for both typescript and python
# ─────────────────────────────────────────────────────────
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
BOLD='\033[1m'
CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
RESET='\033[0m'

print_header() { echo -e "\n${CYAN}━━━ $1 ━━━${RESET}\n"; }
print_ok()     { echo -e "${GREEN}✓ $1${RESET}"; }
print_fail()   { echo -e "${RED}✗ $1${RESET}"; }

EXIT_CODE=0

# ─── NestJS unit test coverage ────────────────────────────
print_header "NestJS unit test coverage"
cd "$ROOT_DIR/core"
if npx jest --coverage --silent 2>&1; then
  print_ok "unit coverage report → core/coverage/"
else
  print_fail "unit tests had failures"
  EXIT_CODE=1
fi

# ─── NestJS e2e test coverage ─────────────────────────────
print_header "NestJS e2e test coverage"
if npx jest --config ./test/jest-e2e.json --coverage --coverageDirectory=./coverage-e2e --silent 2>&1; then
  print_ok "e2e coverage report  → core/coverage-e2e/"
else
  print_fail "e2e tests had failures"
  EXIT_CODE=1
fi

cd "$ROOT_DIR"

# ─── Python test coverage ────────────────────────────────
print_header "Python test coverage"
if python -m pytest \
  tests/ \
  modules/context-module/ \
  modules/payload-gen-module/ \
  modules/fuzzer-module/ \
  --cov=modules/context-module \
  --cov=modules/payload-gen-module \
  --cov=modules/fuzzer-module \
  --cov-report=term-missing \
  --cov-report=html:coverage-python \
  --cov-report=lcov:coverage-python/lcov.info \
  --cov-report=json:coverage-python/coverage.json \
  --cov-config=.coveragerc \
  -q 2>&1; then
  print_ok "python coverage report → coverage-python/"
else
  print_fail "python tests had failures"
  EXIT_CODE=1
fi

# ─── Summary ─────────────────────────────────────────────
print_header "Coverage reports"
echo -e "${BOLD}TypeScript unit:${RESET}   file://$ROOT_DIR/core/coverage/index.html"
echo -e "${BOLD}TypeScript e2e:${RESET}    file://$ROOT_DIR/core/coverage-e2e/index.html"
echo -e "${BOLD}Python:${RESET}            file://$ROOT_DIR/coverage-python/index.html"
echo ""

if [ $EXIT_CODE -eq 0 ]; then
  print_ok "all coverage reports generated successfully"
else
  print_fail "some test suites failed — check output above"
fi

exit $EXIT_CODE
