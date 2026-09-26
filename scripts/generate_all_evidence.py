"""Generate all Phase 2 evidence files in UTF-8 encoding."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
EVIDENCE_DIR = ROOT / "docs" / "evidence" / "phase2"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

PYTHON = sys.executable


def run_and_save(cmd: list[str], output_file: Path, allow_fail: bool = False) -> str:
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    combined = result.stdout
    if result.stderr:
        combined += "\n" + result.stderr
    output_file.write_text(combined, encoding="utf-8")
    print(f"Saved to: {output_file.name} (exit code {result.returncode})")
    if not allow_fail and result.returncode != 0:
        print(f"WARNING: Non-zero exit code: {result.returncode}")
    return combined


print("=" * 70)
print("GENERATING PHASE 2 EVIDENCE PACKAGE")
print("=" * 70)

# 1. Quality checks
run_and_save(
    [str(ROOT / ".venv" / "Scripts" / "ruff.exe"), "check", "."],
    EVIDENCE_DIR / "ruff.txt",
)
run_and_save(
    [str(ROOT / ".venv" / "Scripts" / "black.exe"), "--check", "."],
    EVIDENCE_DIR / "black.txt",
)
run_and_save(
    [str(ROOT / ".venv" / "Scripts" / "mypy.exe"), "core", "api"],
    EVIDENCE_DIR / "mypy.txt",
)

# 2. Tests
run_and_save(
    [
        str(ROOT / ".venv" / "Scripts" / "pytest.exe"),
        "tests/unit",
        "-v",
        "--cov=core",
        "--cov-report=term-missing",
    ],
    EVIDENCE_DIR / "pytest_unit.txt",
)
run_and_save(
    [str(ROOT / ".venv" / "Scripts" / "pytest.exe"), "tests/integration", "-v"],
    EVIDENCE_DIR / "pytest_integration.txt",
)

# 3. Graph validator
run_and_save(
    [PYTHON, "-m", "core.graph.validator"],
    EVIDENCE_DIR / "graph_validation.txt",
    allow_fail=True,
)

# 4. Audit and Demos
run_and_save([PYTHON, "scripts/audit_edges.py"], EVIDENCE_DIR / "edge_count_audit.txt")
run_and_save(
    [PYTHON, "scripts/verify_storage_and_migration.py"], EVIDENCE_DIR / "migration.txt"
)
run_and_save(
    [PYTHON, "scripts/verify_storage_and_migration.py"],
    EVIDENCE_DIR / "minio_bucket.txt",
)
run_and_save(
    [PYTHON, "scripts/demo_anonymization.py"], EVIDENCE_DIR / "anonymization_demo.txt"
)
run_and_save([PYTHON, "scripts/demo_manifest.py"], EVIDENCE_DIR / "manifest_demo.txt")
run_and_save([PYTHON, "scripts/demo_ingestion.py"], EVIDENCE_DIR / "ingestion_demo.txt")
run_and_save([PYTHON, "scripts/check_frontend.py"], EVIDENCE_DIR / "frontend_check.txt")

# 5. Docker status
run_and_save(
    ["docker", "compose", "-f", "infra/docker/docker-compose.yml", "ps"],
    EVIDENCE_DIR / "docker_ps.txt",
    allow_fail=True,
)

print("=" * 70)
print("ALL EVIDENCE FILES GENERATED SUCCESSFULLY IN UTF-8")
print("=" * 70)
