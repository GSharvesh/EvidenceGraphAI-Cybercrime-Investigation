#!/usr/bin/env bash
set -e

echo "=== Running EvidenceGraphAI Test Suite ==="
pytest tests/unit -v --cov=core --cov-report=term-missing
echo "=== Test Suite PASSED cleanly! ==="
