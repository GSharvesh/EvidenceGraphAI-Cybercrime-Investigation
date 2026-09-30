#!/usr/bin/env bash
# EvidenceGraphAI Sandbox Attack Script — Generic CVE Replay Template
#
# This script is executed inside the attacker container by the SandboxReplayAgent.
# It simulates common post-exploitation steps for network-reachable CVEs.
# Telemetry is captured by the tcpdump sidecar running in parallel.
#
# Usage (inside attacker container):
#   bash /scripts/generic_attack.sh

set -euo pipefail

VICTIM="${VICTIM_HOST:-victim}"
LOG_PREFIX="[REPLAY-$(date +%H%M%S)]"

echo "$LOG_PREFIX T1190: Probing public-facing application on $VICTIM:8080"
curl -sk --max-time 5 "http://$VICTIM:8080/" || true

echo "$LOG_PREFIX T1046: Network service discovery"
nc -zv "$VICTIM" 22 2>&1 || true
nc -zv "$VICTIM" 80 2>&1 || true
nc -zv "$VICTIM" 443 2>&1 || true

echo "$LOG_PREFIX T1082: System information discovery"
uname -a
id
hostname

echo "$LOG_PREFIX T1059: Command interpreter invocation"
bash -c "echo 'simulation of T1059'"

echo "$LOG_PREFIX Replay complete. Telemetry captured to /captures/"
echo "$LOG_PREFIX Done"
