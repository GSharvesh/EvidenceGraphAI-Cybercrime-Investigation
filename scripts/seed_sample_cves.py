#!/usr/bin/env python3
"""Seed sample CVEs into the EvidenceGraphAI Vulnerability Intelligence pipeline.

This script demonstrates the Phase 3 pipeline end-to-end by:
1. Analyzing a set of well-known CVEs via the Vulnerability Intelligence Agent.
2. Generating ATT&CK blueprints for each analyzed CVE.
3. Running dry-run sandbox replays.
4. Printing a summary report.

Usage:
    python scripts/seed_sample_cves.py
    python scripts/seed_sample_cves.py --cves CVE-2021-44228 CVE-2023-38831
    python scripts/seed_sample_cves.py --dry-run-only   # Skip NVD fetch, use mock data
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.logging.logger import configure_logging, get_logger

configure_logging(level="INFO", as_json=False)
logger = get_logger("scripts.seed_sample_cves")

# Well-known CVEs for demonstration
SAMPLE_CVES = [
    "CVE-2021-44228",  # Log4Shell — CVSS 10.0
    "CVE-2023-38831",  # WinRAR RCE — CVSS 7.8
    "CVE-2022-22965",  # Spring4Shell — CVSS 9.8
    "CVE-2021-21985",  # VMware vCenter RCE — CVSS 9.8
    "CVE-2017-0144",  # EternalBlue — CVSS 8.1
]


def analyze_cve(cve_id: str) -> dict | None:
    """Analyzes a single CVE using the Vulnerability Intelligence Agent."""
    try:
        from core.agents.vulnerability.agent import VulnerabilityIntelligenceAgent

        agent = VulnerabilityIntelligenceAgent()
        result = agent.analyze(cve_id=cve_id)
        logger.info(
            "CVE analyzed",
            cve_id=cve_id,
            cvss_score=result.cvss_score,
            severity=result.severity,
            techniques=len(result.technique_mappings),
        )
        return result.model_dump(exclude={"raw_nvd_data"})
    except Exception as exc:
        logger.error("CVE analysis failed", cve_id=cve_id, error=str(exc))
        return None


def generate_blueprint(cve_id: str) -> dict | None:
    """Generates a threat blueprint for an analyzed CVE."""
    try:
        from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent

        agent = ThreatReconstructionAgent()
        bp = agent.blueprint(cve_id=cve_id)
        logger.info(
            "Blueprint generated",
            blueprint_id=bp.blueprint_id,
            cve_id=cve_id,
            techniques=len(bp.techniques),
            confidence=bp.total_confidence,
        )
        return bp.model_dump()
    except Exception as exc:
        logger.error("Blueprint generation failed", cve_id=cve_id, error=str(exc))
        return None


def run_sandbox_replay(cve_id: str) -> dict | None:
    """Runs a dry-run sandbox replay for a CVE blueprint."""
    try:
        from core.agents.sandbox_replay.agent import SandboxReplayAgent

        # Load blueprint from graph
        from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent

        tr_agent = ThreatReconstructionAgent()
        bp = tr_agent.blueprint(cve_id=cve_id)

        replay_agent = SandboxReplayAgent(dry_run=True)
        session = replay_agent.replay(blueprint=bp)
        logger.info(
            "Sandbox replay complete",
            session_id=session.session_id,
            status=session.status,
            artifacts=len(session.telemetry_artifacts),
        )
        return session.model_dump()
    except Exception as exc:
        logger.error("Replay failed", cve_id=cve_id, error=str(exc))
        return None


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Seed sample CVEs into EvidenceGraphAI Phase 3"
    )
    parser.add_argument("--cves", nargs="*", help="Specific CVE IDs to analyze")
    parser.add_argument(
        "--dry-run-only",
        action="store_true",
        help="Skip NVD fetch (not implemented — use for testing)",
    )
    parser.add_argument(
        "--no-blueprint", action="store_true", help="Skip blueprint generation"
    )
    parser.add_argument("--no-replay", action="store_true", help="Skip sandbox replay")
    parser.add_argument(
        "--output", type=str, default=None, help="Write results to JSON file"
    )
    args = parser.parse_args()

    cves = args.cves or SAMPLE_CVES
    results: dict = {"timestamp": datetime.now(UTC).isoformat(), "cves": {}}

    print("\n" + "=" * 60)
    print("EvidenceGraphAI — Phase 3 CVE Seeding Script")
    print("=" * 60)
    print(f"Processing {len(cves)} CVE(s): {', '.join(cves)}\n")

    for cve_id in cves:
        cve_id = cve_id.strip().upper()
        print(f"\n{'─'*50}")
        print(f"CVE: {cve_id}")
        print("─" * 50)
        cve_result: dict = {"cve_id": cve_id}

        # Step 1: Analyze
        print(f"  [1/3] Analyzing {cve_id} (fetching from NVD + caching)...")
        analysis = analyze_cve(cve_id)
        if analysis:
            cve_result["analysis"] = {
                "cvss_score": analysis.get("cvss_score"),
                "severity": analysis.get("severity"),
                "technique_count": len(analysis.get("technique_mappings", [])),
                "node_id": analysis.get("node_id"),
            }
            print(
                f"      ✓ CVSS={analysis.get('cvss_score')} Severity={analysis.get('severity')} Techniques={len(analysis.get('technique_mappings', []))}"
            )
        else:
            print("      ✗ Analysis failed")
            cve_result["analysis"] = None
            results["cves"][cve_id] = cve_result
            continue

        # Step 2: Blueprint
        if not args.no_blueprint:
            print("  [2/3] Generating threat blueprint...")
            bp = generate_blueprint(cve_id)
            if bp:
                cve_result["blueprint"] = {
                    "blueprint_id": bp.get("blueprint_id"),
                    "technique_count": len(bp.get("techniques", [])),
                    "confidence": bp.get("total_confidence"),
                }
                print(
                    f"      ✓ Blueprint {bp['blueprint_id']} ({len(bp.get('techniques',[]))} techniques, confidence={bp.get('total_confidence'):.2f})"
                )
            else:
                print("      ✗ Blueprint generation failed")
                cve_result["blueprint"] = None
        else:
            print("  [2/3] Blueprint skipped (--no-blueprint)")

        # Step 3: Replay
        if not args.no_replay:
            print("  [3/3] Running dry-run sandbox replay...")
            session = run_sandbox_replay(cve_id)
            if session:
                cve_result["replay"] = {
                    "session_id": session.get("session_id"),
                    "status": session.get("status"),
                    "artifact_count": len(session.get("telemetry_artifacts", [])),
                    "confirmed": len(
                        [
                            t
                            for t in session.get("technique_results", [])
                            if t["status"] == "confirmed"
                        ]
                    ),
                }
                print(
                    f"      ✓ Session {session['session_id']} status={session['status']}"
                )
            else:
                print("      ✗ Replay failed")
                cve_result["replay"] = None
        else:
            print("  [3/3] Replay skipped (--no-replay)")

        results["cves"][cve_id] = cve_result

    # Summary
    print("\n" + "=" * 60)
    print("SEEDING SUMMARY")
    print("=" * 60)
    total = len(results["cves"])
    analyzed = sum(1 for v in results["cves"].values() if v.get("analysis"))
    blueprinted = sum(1 for v in results["cves"].values() if v.get("blueprint"))
    replayed = sum(
        1
        for v in results["cves"].values()
        if v.get("replay") and v["replay"].get("status") == "completed"
    )
    print(f"  CVEs processed:  {total}")
    print(f"  Analyzed:        {analyzed}/{total}")
    print(f"  Blueprinted:     {blueprinted}/{total}")
    print(f"  Replayed (pass): {replayed}/{total}")

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(
            json.dumps(results, indent=2, default=str), encoding="utf-8"
        )
        print(f"\n  Results written to {out_path}")

    print("\nDone.")


if __name__ == "__main__":
    main()
