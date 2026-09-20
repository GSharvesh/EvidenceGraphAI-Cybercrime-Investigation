#!/usr/bin/env bash
set -e

echo "=== Running Code Linter & Formatter Verification ==="
ruff check .
black --check .
echo "=== Lint check PASSED cleanly! ==="
