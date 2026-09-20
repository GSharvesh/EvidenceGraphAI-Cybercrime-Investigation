#!/usr/bin/env bash
set -e

echo "========================================================"
echo "      EvidenceGraphAI Phase 0 Full Validation Suite     "
echo "========================================================"

echo "[1/4] Code Linting & Formatting Check (Ruff & Black)..."
ruff check .
black --check .

echo "[2/4] Static Type Checking (MyPy)..."
mypy core api

echo "[3/4] Unit Test Suite & Coverage (PyTest)..."
pytest tests/unit -v --cov=core --cov-report=term-missing

echo "========================================================"
echo "  [SUCCESS] All Phase 0 Validation Checks Passed Cleanly! "
echo "========================================================"
