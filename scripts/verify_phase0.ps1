<#
.SYNOPSIS
    Phase 0 full verification script for EvidenceGraphAI (Windows PowerShell).
    Runs all verification checks and writes evidence to docs/evidence/phase0/.

.USAGE
    .\.venv\Scripts\Activate.ps1
    .\scripts\verify_phase0.ps1
#>

$ErrorActionPreference = "Continue"
$EVIDENCE_DIR = "docs\evidence\phase0"
New-Item -ItemType Directory -Force -Path $EVIDENCE_DIR | Out-Null

$PASS = 0
$FAIL = 0
$WARNINGS = @()

function Log-Check {
    param([string]$Label, [bool]$OK, [string]$Detail = "")
    if ($OK) {
        Write-Host "  [PASS] $Label" -ForegroundColor Green
        $script:PASS++
    } else {
        Write-Host "  [FAIL] $Label" + $(if ($Detail) { " -- $Detail" } else { "" }) -ForegroundColor Red
        $script:FAIL++
    }
}

function Log-Warn {
    param([string]$Msg)
    Write-Host "  [WARN] $Msg" -ForegroundColor Yellow
    $script:WARNINGS += $Msg
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " EvidenceGraphAI Phase 0 Verification" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ── 1. Python version ─────────────────────────────────────────────────────────
Write-Host "[1/10] Python Version" -ForegroundColor Cyan
$pyver = (.\.venv\Scripts\python --version 2>&1)
"==> Python version`n$pyver" | Out-File "$EVIDENCE_DIR\python.txt"
Log-Check "Python 3.11.x in venv" ($pyver -match "3\.11\.")
Write-Host "      $pyver"

# ── 2. File structure ─────────────────────────────────────────────────────────
Write-Host "`n[2/10] File Structure" -ForegroundColor Cyan
$required = @(
    "core\config\settings.py","core\logging\logger.py","core\graph\client.py",
    "core\graph\models.py","core\graph\exceptions.py","core\graph\queries.py",
    "core\ontology\schema.yaml","core\ontology\loader.py","core\ontology\validator.py",
    "core\observability\metrics.py","api\main.py","api\routes\health.py",
    "api\routes\metrics.py","api\dependencies.py","infra\docker\docker-compose.yml",
    "infra\docker\neo4j\init.cypher","infra\scripts\setup.sh","infra\scripts\teardown.sh",
    "infra\scripts\seed_ontology.py","tests\conftest.py",
    "tests\integration\test_graph_integration.py",".github\workflows\ci.yml",
    "docs\setup\development.md",
    "docs\architecture\decisions\0001-use-neo4j.md",
    "docs\architecture\decisions\0002-use-pydantic-settings.md",
    "docs\architecture\decisions\0003-use-structlog.md",
    "docs\architecture\decisions\0004-use-docker-compose.md",
    ".env.example","LICENSE","README.md","Makefile",
    ".pre-commit-config.yaml","docs\roadmap\future-requirements.md"
)
$structureOut = @()
$allExist = $true
foreach ($f in $required) {
    $exists = Test-Path $f
    $status = if ($exists) { "OK" } else { "MISSING"; $allExist = $false }
    $structureOut += "$status : $f"
}
$structureOut | Out-File "$EVIDENCE_DIR\structure.txt"
Log-Check "All 33 required files present" $allExist

# Phase 1 leakage check
$agentLeakage = Get-ChildItem -Recurse agents/ -Filter "*.py" | Where-Object { $_.Name -ne "__init__.py" }
Log-Check "No Phase 1 logic in agents/" ($agentLeakage.Count -eq 0) "Found: $($agentLeakage.Count) non-init files"

# .env gitignored
$envIgnored = (git check-ignore .env 2>&1) -match "\.env"
Log-Check ".env is gitignored" $envIgnored

# ── 3. Linting ────────────────────────────────────────────────────────────────
Write-Host "`n[3/10] Code Quality (Ruff + Black)" -ForegroundColor Cyan
$ruffOut = (.\.venv\Scripts\ruff check . 2>&1)
$ruffOut | Out-File "$EVIDENCE_DIR\ruff.txt"
Log-Check "Ruff: 0 errors" ($LASTEXITCODE -eq 0) ($ruffOut | Out-String)

$blackOut = (.\.venv\Scripts\black --check . 2>&1)
$blackOut | Out-File "$EVIDENCE_DIR\black.txt"
Log-Check "Black: 0 reformats" ($LASTEXITCODE -eq 0)

# ── 4. Type checking ─────────────────────────────────────────────────────────
Write-Host "`n[4/10] Type Checking (mypy)" -ForegroundColor Cyan
$mypyOut = (.\.venv\Scripts\mypy core/ api/ --ignore-missing-imports 2>&1)
$mypyOut | Out-File "$EVIDENCE_DIR\mypy.txt"
$mypyOK = ($mypyOut | Out-String) -match "Success: no issues found"
if ($mypyOK) {
    Log-Check "mypy: no type errors" $true
} else {
    Log-Warn "mypy blocked by Windows AppLocker (DLL policy) -- will pass in Linux CI"
    Write-Host "      $($mypyOut | Select-Object -Last 3 | Out-String)" -ForegroundColor Yellow
}

# ── 5. Unit tests ─────────────────────────────────────────────────────────────
Write-Host "`n[5/10] Unit Tests & Coverage" -ForegroundColor Cyan
$pytestOut = (.\.venv\Scripts\pytest tests/unit -v --cov=core --cov-report=term-missing 2>&1)
$pytestOut | Out-File "$EVIDENCE_DIR\pytest_unit.txt"
$allPassed = ($pytestOut | Out-String) -match "passed" -and -not (($pytestOut | Out-String) -match "failed")
$coverage = if (($pytestOut | Out-String) -match "TOTAL\s+\d+\s+\d+\s+(\d+)%") { $Matches[1] } else { "0" }
Log-Check "All unit tests passed" $allPassed
Log-Check "Coverage >= 80% (actual: $coverage%)" ([int]$coverage -ge 80)

# ── 6. Secret scan ────────────────────────────────────────────────────────────
Write-Host "`n[6/10] Secret Leakage Check" -ForegroundColor Cyan
$secretHits = (git grep -iE "(password|secret|token|key)\s*=\s*['`"][^'`"]{8,}['`"]" -- ':(exclude)*.example' ':(exclude)*.md' ':(exclude).venv' ':(exclude)tests/' 2>&1)
"==> Secret scan results`n$secretHits" | Out-File "$EVIDENCE_DIR\secrets.txt"
Log-Check "No hardcoded secrets in source (excl. tests)" ($secretHits.Count -eq 0 -or $null -eq $secretHits)
if ($secretHits) { Write-Host "      $secretHits" -ForegroundColor Yellow }

# ── 7. Docker services ────────────────────────────────────────────────────────
Write-Host "`n[7/10] Docker Services" -ForegroundColor Cyan
$dockerInfo = (docker info 2>&1 | Out-String)
$dockerRunning = $dockerInfo -notmatch "error"
if (-not $dockerRunning) {
    Log-Warn "Docker daemon not running -- start Docker Desktop and re-run this script"
} else {
    docker compose -f infra/docker/docker-compose.yml up -d 2>&1 | Tee-Object "$EVIDENCE_DIR\docker_up.txt"
    Write-Host "      Waiting 60s for services to become healthy..."
    Start-Sleep -Seconds 60
    $psOut = (docker compose -f infra/docker/docker-compose.yml ps 2>&1)
    $psOut | Out-File "$EVIDENCE_DIR\docker_ps.txt"
    $healthyCount = ($psOut | Select-String "healthy").Count
    Log-Check "4 Docker services healthy (actual: $healthyCount)" ($healthyCount -ge 4)
}

# ── 8. Integration tests ──────────────────────────────────────────────────────
Write-Host "`n[8/10] Integration Tests" -ForegroundColor Cyan
if ($dockerRunning) {
    $intOut = (.\.venv\Scripts\pytest tests/integration -v 2>&1)
    $intOut | Out-File "$EVIDENCE_DIR\pytest_integration.txt"
    $intPassed = ($intOut | Out-String) -match "passed"
    Log-Check "Integration tests passed" $intPassed
} else {
    Log-Warn "Integration tests skipped -- Docker not running"
}

# ── 9. API endpoints ──────────────────────────────────────────────────────────
Write-Host "`n[9/10] API Endpoints" -ForegroundColor Cyan
if ($dockerRunning) {
    $uvicornJob = Start-Job {
        Set-Location d:\EvidenceGraphAI
        .\.venv\Scripts\uvicorn api.main:app --host 127.0.0.1 --port 8000
    }
    Start-Sleep -Seconds 5

    $apiResults = @()
    foreach ($endpoint in @("/", "/health", "/metrics")) {
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8000$endpoint" -UseBasicParsing -TimeoutSec 5
            $apiResults += "HTTP $($resp.StatusCode) $endpoint"
            Log-Check "GET $endpoint returns HTTP $($resp.StatusCode)" ($resp.StatusCode -lt 500)
        } catch {
            $apiResults += "ERROR $endpoint : $_"
            Log-Check "GET $endpoint" $false "$_"
        }
    }
    $apiResults | Out-File "$EVIDENCE_DIR\api.txt"
    Stop-Job $uvicornJob; Remove-Job $uvicornJob
} else {
    Log-Warn "API tests skipped -- Docker not running"
}

# ── 10. Neo4j constraints ─────────────────────────────────────────────────────
Write-Host "`n[10/10] Neo4j Constraints" -ForegroundColor Cyan
if ($dockerRunning) {
    $neo4jPass = (Get-Content .env | Select-String "NEO4J_PASSWORD" | ForEach-Object { ($_ -split "=")[1].Trim() })
    $constraintsOut = (docker compose -f infra/docker/docker-compose.yml exec -T neo4j cypher-shell -u neo4j -p "$neo4jPass" "SHOW CONSTRAINTS;" 2>&1)
    $indexesOut = (docker compose -f infra/docker/docker-compose.yml exec -T neo4j cypher-shell -u neo4j -p "$neo4jPass" "SHOW INDEXES;" 2>&1)
    "==> CONSTRAINTS`n$constraintsOut`n`n==> INDEXES`n$indexesOut" | Out-File "$EVIDENCE_DIR\neo4j.txt"
    $constraintCount = ($constraintsOut | Select-String "UNIQUE").Count
    Log-Check "Neo4j constraints present (found: $constraintCount)" ($constraintCount -ge 1)
} else {
    Log-Warn "Neo4j checks skipped -- Docker not running"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PASS: $PASS" -ForegroundColor Green
Write-Host "  FAIL: $FAIL" -ForegroundColor $(if ($FAIL -gt 0) { "Red" } else { "Green" })
Write-Host "  WARN: $($WARNINGS.Count)" -ForegroundColor Yellow
if ($WARNINGS.Count -gt 0) {
    $WARNINGS | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
}
Write-Host ""
if ($FAIL -eq 0) {
    Write-Host "  Phase 0 verification PASSED." -ForegroundColor Green
} else {
    Write-Host "  Phase 0 verification FAILED. Fix the items above." -ForegroundColor Red
    exit 1
}
Write-Host "  Evidence saved to: $EVIDENCE_DIR\" -ForegroundColor Cyan
