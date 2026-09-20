#!/usr/bin/env bash
set -e

echo "=== EvidenceGraphAI Infrastructure Setup ==="
docker compose -f infra/docker/docker-compose.yml up -d

echo "Waiting for Neo4j service health..."
until [ "$(docker inspect --format='{{.State.Health.Status}}' evidencegraphai-neo4j 2>/dev/null)" == "healthy" ]; do
    echo "Waiting for Neo4j to become healthy..."
    sleep 3
done

echo "Neo4j is healthy. Seeding ontology constraints and indexes..."
python infra/scripts/seed_ontology.py

echo "=== Infrastructure setup completed successfully! ==="
