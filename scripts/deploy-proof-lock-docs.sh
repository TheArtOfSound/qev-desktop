#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT/proof-lock-web"
DOCS_DIR="$ROOT/docs"

echo "[proof-lock] root: $ROOT"
cd "$ROOT"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required but was not found" >&2
  exit 1
fi

echo "[proof-lock] installing web dependencies"
npm --prefix "$APP_DIR" install

echo "[proof-lock] building web app"
npm --prefix "$APP_DIR" run build

echo "[proof-lock] replacing docs/ with built app"
rm -rf "$DOCS_DIR"
mkdir -p "$DOCS_DIR"
cp -R "$APP_DIR/dist/." "$DOCS_DIR/"

# GitHub Pages fallback for direct refreshes.
cp "$DOCS_DIR/index.html" "$DOCS_DIR/404.html"

echo "[proof-lock] committing built Pages app"
git add docs proof-lock-web scripts/deploy-proof-lock-docs.sh
if git diff --cached --quiet; then
  echo "[proof-lock] no changes to commit"
else
  git commit -m "Deploy Proof Lock web app to docs"
fi

echo "[proof-lock] pushing main"
git push origin main

echo "[proof-lock] done"
echo "Now set GitHub Pages to: Deploy from a branch -> main -> /docs"
echo "Then open: https://theartofsound.github.io/qev-desktop/"
