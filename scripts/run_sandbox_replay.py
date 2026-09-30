#!/usr/bin/env python3
"""Run a sandbox attack replay for a CVE blueprint.

Usage:
    python scripts/run_sandbox_replay.py --cve-id CVE-2021-44228 --dry-run
    python scripts/run_sandbox_replay.py --cve-id CVE-2021-44228 --live
"""

from __future__ import annotations

import argparse
import json
import sys

from core.agents.sandbox_replay.agent import SandboxReplayAgent
from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent
from core.agents.vulnerability.agent import VulnerabilityIntelligenceAgent
from core.logging.logger import get_logger

logger = get_logger("scripts.run_sandbox_replay")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute a sandbox attack replay for a CVE blueprint"
    )
    parser.add_argument(
        "--cve-id",
        required=True,
        help="CVE identifier to replay (e.g. CVE-2021-44228)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Run in dry-run mode (synthesizes telemetry without starting Docker containers)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run in live Docker mode (requires Docker daemon and sandbox images)",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Print session result as formatted JSON",
    )

    args = parser.parse_args()
    dry_run = not args.live if args.live else args.dry_run

    print(f"[*] Analyzing {args.cve_id} via Vulnerability Intelligence Agent...")
    vuln_agent = VulnerabilityIntelligenceAgent()
    vuln_agent.analyze(args.cve_id, actor="sandbox_runner")

    print(f"[*] Generating threat blueprint for {args.cve_id}...")
    tr_agent = ThreatReconstructionAgent()
    bp = tr_agent.blueprint(args.cve_id, actor="sandbox_runner")
    print(
        f"[+] Blueprint generated: {bp.blueprint_id} ({len(bp.techniques)} techniques)"
    )

    mode_str = "DRY-RUN (synthetic)" if dry_run else "LIVE (isolated Docker)"
    print(f"[*] Starting sandbox replay in {mode_str} mode...")
    replay_agent = SandboxReplayAgent(dry_run=dry_run)
    session = replay_agent.replay(blueprint=bp, actor="sandbox_runner")

    print(f"[+] Session complete: {session.session_id} (status: {session.status})")
    print(f"[+] Telemetry artifacts generated: {len(session.telemetry_artifacts)}")
    for art in session.telemetry_artifacts:
        print(
            f"    - [{art.artifact_type}] {art.object_name} (SHA256: {art.sha256[:12]}...)"
        )

    if args.output_json:
        print("\n" + json.dumps(session.model_dump(), indent=2, default=str))

    return 0 if session.status == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
