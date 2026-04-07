#!/usr/bin/env bash
set -euo pipefail

git config core.hooksPath .githooks
chmod +x .githooks/pre-push

echo "Local guardrails enabled."
echo "- hooksPath: .githooks"
echo "- pre-push: validates branch naming, blocks direct main push, checks formatting, runs tests, and runs gitleaks when available"
echo "- CI: validates PR titles and runs secret scanning and test checks"
