# Sandbox Subsystem Overview

## Purpose

The EvidenceGraphAI Sandbox is an air-gapped execution environment designed to safely simulate exploit behaviors and generate empirical forensic artifacts (PCAP network traces, system audit logs, application telemetry). This telemetry is ingested by the framework to validate or refute hypothetical threat blueprints.

## Architecture

The sandbox is defined in `infra/sandbox/docker-compose.yml` and consists of three tiers:

1. **Target Tier:** Intentionally vulnerable application containers (e.g. `log4j-vulnerable` with Log4j 2.14.1, `dvwa`, `juice-shop`, `metasploitable`).
2. **Attacker Tier:** Minimal execution container equipped with standard offensive/defensive probe tooling (`curl`, `nmap`, `netcat`, `python3`).
3. **Collector Tier:** Sidecar container attached to network namespaces capturing continuous traffic (`tcpdump`) into `/captures/*.pcap`.

## Isolation Guarantee

- Network mode is strictly `internal: true`.
- Zero host port bindings by default.
- No outbound internet egress (tested and enforced by `infra/sandbox/scripts/verify_isolation.sh`).
