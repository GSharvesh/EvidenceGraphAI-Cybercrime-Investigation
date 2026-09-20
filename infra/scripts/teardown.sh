#!/usr/bin/env bash
set -e

echo "=== EvidenceGraphAI Infrastructure Teardown ==="
docker compose -f infra/docker/docker-compose.yml down -v
echo "=== Teardown complete. Named volumes removed. ==="
