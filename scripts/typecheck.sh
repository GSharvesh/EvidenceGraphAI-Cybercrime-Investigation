#!/usr/bin/env bash
set -e

echo "=== Running Static Type Checker (MyPy) ==="
mypy core api
echo "=== Typecheck PASSED cleanly with 0 errors! ==="
