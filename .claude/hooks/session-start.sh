#!/bin/bash
# Vouch Protocol SessionStart hook for Claude Code on the web.
# Installs the dependencies needed to run tests and linters so they are
# available before the session starts. Safe to run repeatedly.
set -euo pipefail

# Only run in remote (Claude Code on the web) environments.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"

# Python: install the package in editable mode with the dev extras.
# This pulls pytest, ruff, pytest-asyncio, and the media test deps
# (Pillow, base58, qrcode, c2pa-python) declared in pyproject.toml.
pip install -e ".[dev]" --quiet

# TypeScript SDK: install deps so `vitest`, `tsc`, and the build run.
# Best-effort: a network hiccup here should not block the session.
if [ -d packages/sdk-ts ] && command -v npm >/dev/null 2>&1; then
  (cd packages/sdk-ts && npm install --no-audit --no-fund --silent) \
    || echo "warning: sdk-ts npm install failed; TS tests may be unavailable"
fi

echo "Vouch dev dependencies ready (Python .[dev] + sdk-ts npm)."
