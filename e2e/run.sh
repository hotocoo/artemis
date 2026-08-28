#!/usr/bin/env bash
# Build everything, install the browser, and run the full e2e chaos workflow.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Building solution (Debug)..."
dotnet build Artemis.slnx -c Debug --nologo -v q

echo "==> Ensuring Playwright + Chromium..."
cd e2e
if [ ! -d node_modules ]; then
  npm install --no-audit --no-fund
fi
npx playwright install chromium --with-deps 2>/dev/null || npx playwright install chromium

echo "==> Running e2e chaos workflow..."
node chaos.mjs
