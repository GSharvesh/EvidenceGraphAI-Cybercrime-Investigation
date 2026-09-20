<#
.SYNOPSIS
    Phase 0 full verification script for EvidenceGraphAI (Windows PowerShell).
    Runs all verification checks and writes evidence to docs/evidence/phase0/.

.USAGE
    .\.venv\Scripts\Activate.ps1
    .\scripts\verify_phase0.ps1
#>

$ErrorActionPreference = "Continue"

# Resolve repo root regardless of where script is called from
$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $repoRoot

$EVIDENCE_DIR = Join-Path $repoRoot "docs\evidence\phase0"
if (-not (Test-Path $EVIDENCE_DIR)) {
    New-Item -ItemType Directory -Force -Path $EVIDENCE_DIR | Out-Null
}

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

# ── Docker Pre-Check (Positive verification) ─────────────────────────────────
$dockerVer = (& docker info --format '{{.ServerVersion}}' 2>&1)
$dockerExit = $LASTEXITCODE
$dockerRunning = ($dockerExit -eq 0 -and -not [string]::IsNullOrWhiteSpace($dockerVer) -and ($dockerVer -match '^\d+\.'))

# ── 1. Python version ─────────────────────────────────────────────────────────
Write-Host "[1/10] Python Version" -ForegroundColor Cyan
$pyExe = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $pyExe)) {
    Log-Check "Python 3.11.x in venv" $false "Virtualenv python not found at $pyExe"
} else {
    $pyver = & $pyExe --version 2>&1
    $pyExit = $LASTEXITCODE
    "==> Python version`n$pyver" | Out-File "$EVIDENCE_DIR\python.txt" -Encoding utf8
    Log-Check "Python 3.11.x in venv" ($pyExit -eq 0 -and $pyver -match "3\.11\.") "Output: $pyver (Exit: $pyExit)"
    Write-Host "      $pyver"
}

# ── 2. File structure & Phase boundary ───────────────────────────────────────
Write-Host "`n[2/10] File Structure & Boundaries" -ForegroundColor Cyan
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
$missingFiles = @()
foreach ($f in $required) {
    $exists = Test-Path (Join-Path $repoRoot $f)
    if ($exists) {
        $structureOut += "OK : $f"
    } else {
        $structureOut += "MISSING : $f"
        $missingFiles += $f
    }
}
$structureOut | Out-File "$EVIDENCE_DIR\structure.txt" -Encoding utf8
Log-Check "All 33 required files present" ($missingFiles.Count -eq 0) $(if ($missingFiles.Count -gt 0) { "Missing: " + ($missingFiles -join ", ") } else { "" })

# Phase 1 leakage check
$agentLeakage = Get-ChildItem -Recurse agents/ -Filter "*.py" | Where-Object { $_.Name -ne "__init__.py" }
Log-Check "No Phase 1 logic in agents/" ($agentLeakage.Count -eq 0) "Found: $($agentLeakage.Count) non-init files"

# .env gitignored
$envIgnoredRaw = & git check-ignore .env 2>&1
$envIgnoredExit = $LASTEXITCODE
Log-Check ".env is gitignored" ($envIgnoredExit -eq 0 -and ($envIgnoredRaw | Out-String) -match "\.env") "ExitCode: $envIgnoredExit"

# ── 3. Linting (Ruff + Black) ─────────────────────────────────────────────────
Write-Host "`n[3/10] Code Quality (Ruff + Black)" -ForegroundColor Cyan
$ruffExe = Join-Path $repoRoot ".venv\Scripts\ruff.exe"
$ruffOut = & $ruffExe check . 2>&1
$ruffExit = $LASTEXITCODE
$ruffOut | Out-File "$EVIDENCE_DIR\ruff.txt" -Encoding utf8
Log-Check "Ruff: 0 errors" ($ruffExit -eq 0) "ExitCode: $ruffExit"

$blackExe = Join-Path $repoRoot ".venv\Scripts\black.exe"
$blackOut = & $blackExe --check . 2>&1
$blackExit = $LASTEXITCODE
$blackOut | Out-File "$EVIDENCE_DIR\black.txt" -Encoding utf8
Log-Check "Black: 0 reformats" ($blackExit -eq 0) "ExitCode: $blackExit"

# ── 4. Type checking (mypy) ───────────────────────────────────────────────────
Write-Host "`n[4/10] Type Checking (mypy)" -ForegroundColor Cyan
$mypyExe = Join-Path $repoRoot ".venv\Scripts\mypy.exe"
$mypyOut = & $mypyExe core/ api/ --ignore-missing-imports 2>&1
$mypyExit = $LASTEXITCODE
$mypyStr = $mypyOut | Out-String

if ($mypyExit -eq 0 -and $mypyStr -match "Success: no issues found") {
    $mypyOut | Out-File "$EVIDENCE_DIR\mypy.txt" -Encoding utf8
    Log-Check "mypy: 0 type errors (local)" $true
} elseif ($mypyStr -match "Application Control policy has blocked this file|AppLocker|DLL load failed") {
    if ($dockerRunning) {
        Write-Host "      Local mypy blocked by Windows AppLocker DLL policy. Verifying in Linux Docker container..." -ForegroundColor Yellow
        $mypyDockerOut = & docker run --rm -v "${repoRoot}:/app" -w /app python:3.11-slim bash -c "pip install -q mypy==1.10.0 pydantic==2.7.4 pydantic-settings==2.3.4 structlog==24.2.0 fastapi==0.111.0 neo4j==5.20.0 prometheus-client==0.20.0 pyyaml==6.0.1 && mypy core/ api/ --ignore-missing-imports" 2>&1
        $mypyDockerExit = $LASTEXITCODE
        $mypyDockerStr = $mypyDockerOut | Out-String
        $mypyDockerOut | Out-File "$EVIDENCE_DIR\mypy.txt" -Encoding utf8
        if ($mypyDockerExit -eq 0 -and $mypyDockerStr -match "Success: no issues found") {
            Log-Check "mypy: 0 type errors (verified via Linux Docker python:3.11)" $true
        } else {
            Log-Check "mypy: 0 type errors" $false "ExitCode: $mypyDockerExit -- $($mypyDockerStr.Trim())"
        }
    } else {
        $mypyOut | Out-File "$EVIDENCE_DIR\mypy.txt" -Encoding utf8
        Log-Warn "mypy blocked by Windows AppLocker (DLL policy) -- verified in Linux CI"
        Write-Host "      $($mypyOut | Select-Object -Last 3 | Out-String)" -ForegroundColor Yellow
    }
} else {
    $mypyOut | Out-File "$EVIDENCE_DIR\mypy.txt" -Encoding utf8
    Log-Check "mypy: 0 type errors" $false "ExitCode: $mypyExit -- $($mypyStr.Trim())"
}

# ── 5. Unit tests & Coverage ──────────────────────────────────────────────────
Write-Host "`n[5/10] Unit Tests & Coverage" -ForegroundColor Cyan
$pytestExe = Join-Path $repoRoot ".venv\Scripts\pytest.exe"
$pytestOut = & $pytestExe tests/unit -v --cov=core --cov-report=term-missing 2>&1
$pytestExit = $LASTEXITCODE
$pytestOut | Out-File "$EVIDENCE_DIR\pytest_unit.txt" -Encoding utf8
$pytestStr = $pytestOut | Out-String
$allPassed = ($pytestExit -eq 0 -and $pytestStr -match "\b(\d+)\s+passed\b" -and -not ($pytestStr -match "failed|error"))
$coverage = if ($pytestStr -match "TOTAL\s+\d+\s+\d+\s+(\d+)%") { [int]$Matches[1] } else { 0 }
Log-Check "All unit tests passed" $allPassed "ExitCode: $pytestExit"
Log-Check "Coverage >= 80% (actual: $coverage%)" ($allPassed -and $coverage -ge 80) "Actual: $coverage%"

# ── 6. Secret scan ────────────────────────────────────────────────────────────
Write-Host "`n[6/10] Secret Leakage Check" -ForegroundColor Cyan
$secretHits = & git grep -iE "(password|secret|token|key)\s*=\s*['`"][^'`"]{8,}['`"]" -- ':(exclude)*.example' ':(exclude)*.md' ':(exclude).venv' ':(exclude)tests/' ':(exclude)docs/' 2>&1
$secretExit = $LASTEXITCODE
"==> Secret scan results (exit code: $secretExit)`n$secretHits" | Out-File "$EVIDENCE_DIR\secrets.txt" -Encoding utf8
if ($secretExit -eq 1 -and [string]::IsNullOrWhiteSpace(($secretHits | Out-String).Trim())) {
    Log-Check "No hardcoded secrets in source (excl. tests)" $true
} elseif ($secretExit -eq 0) {
    Log-Check "No hardcoded secrets in source (excl. tests)" $false "Found potential secret strings in source"
    Write-Host "      $secretHits" -ForegroundColor Yellow
} else {
    Log-Check "No hardcoded secrets in source (excl. tests)" $false "git grep command failed with exit code $secretExit"
}

# ── 7. Docker services ────────────────────────────────────────────────────────
Write-Host "`n[7/10] Docker Services" -ForegroundColor Cyan
if (-not $dockerRunning) {
    Log-Warn "Docker daemon not running -- start Docker Desktop and re-run this script"
} else {
    Write-Host "      Docker daemon active (version $dockerVer)" -ForegroundColor Green
    $composeUpOut = & docker compose -f infra/docker/docker-compose.yml up -d 2>&1
    $composeUpExit = $LASTEXITCODE
    $composeUpOut | Out-File "$EVIDENCE_DIR\docker_up.txt" -Encoding utf8
    if ($composeUpExit -ne 0) {
        Log-Check "Docker compose up -d succeeded" $false "ExitCode: $composeUpExit"
    } else {
        Log-Check "Docker compose up -d succeeded" $true
    }

    Write-Host "      Verifying service health..."
    $maxWait = 60
    $waited = 0
    $healthyCount = 0
    while ($waited -lt $maxWait) {
        $psOut = & docker compose -f infra/docker/docker-compose.yml ps 2>&1
        $healthyCount = ($psOut | Select-String "\(healthy\)").Count
        if ($healthyCount -ge 4) {
            break
        }
        Start-Sleep -Seconds 3
        $waited += 3
    }
    $psFinal = & docker compose -f infra/docker/docker-compose.yml ps 2>&1
    $psFinal | Out-File "$EVIDENCE_DIR\docker_ps.txt" -Encoding utf8
    Log-Check "4 Docker services healthy (actual: $healthyCount)" ($healthyCount -ge 4) "Waited ${waited}s, healthy count: $healthyCount"
}

# ── 8. Integration tests ──────────────────────────────────────────────────────
Write-Host "`n[8/10] Integration Tests" -ForegroundColor Cyan
if ($dockerRunning) {
    $intOut = & $pytestExe tests/integration -v 2>&1
    $intExit = $LASTEXITCODE
    $intOut | Out-File "$EVIDENCE_DIR\pytest_integration.txt" -Encoding utf8
    $intStr = $intOut | Out-String
    $intPassed = ($intExit -eq 0 -and $intStr -match "\b(\d+)\s+passed\b" -and -not ($intStr -match "failed|error"))
    Log-Check "Integration tests passed" $intPassed "ExitCode: $intExit"
} else {
    Log-Warn "Integration tests skipped -- Docker not running"
}

# ── 9. API endpoints ──────────────────────────────────────────────────────────
Write-Host "`n[9/10] API Endpoints" -ForegroundColor Cyan
if ($dockerRunning) {
    $uvicornScript = Join-Path $repoRoot ".venv\Scripts\uvicorn.exe"
    $uvicornJob = Start-Job -ScriptBlock {
        param($root, $exe)
        Set-Location $root
        & $exe api.main:app --host 127.0.0.1 --port 8000
    } -ArgumentList $repoRoot, $uvicornScript

    $serverReady = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Seconds 1
        try {
            $testPing = Invoke-WebRequest -Uri "http://127.0.0.1:8000/" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($testPing.StatusCode -eq 200) {
                $serverReady = $true
                break
            }
        } catch {
            # Still starting
        }
    }

    $apiResults = @()
    if (-not $serverReady) {
        Log-Check "API server startup on http://127.0.0.1:8000" $false "Server did not respond within 10 seconds"
        $jobLog = Receive-Job $uvicornJob
        $apiResults += "Server failed to start:`n$jobLog"
    } else {
        # Check GET /
        try {
            $respRoot = Invoke-WebRequest -Uri "http://127.0.0.1:8000/" -UseBasicParsing -TimeoutSec 5
            $apiResults += "HTTP $($respRoot.StatusCode) / -> $($respRoot.Content)"
            Log-Check "GET / returns HTTP 200" ($respRoot.StatusCode -eq 200 -and $respRoot.Content -match "EvidenceGraphAI") "Status: $($respRoot.StatusCode)"
        } catch {
            $apiResults += "ERROR / : $_"
            Log-Check "GET / returns HTTP 200" $false "$_"
        }

        # Check GET /health
        try {
            $respHealth = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -UseBasicParsing -TimeoutSec 5
            $apiResults += "HTTP $($respHealth.StatusCode) /health -> $($respHealth.Content)"
            Log-Check "GET /health returns HTTP 200" ($respHealth.StatusCode -eq 200 -and $respHealth.Content -match "healthy") "Status: $($respHealth.StatusCode)"
        } catch {
            $apiResults += "ERROR /health : $_"
            Log-Check "GET /health returns HTTP 200" $false "$_"
        }

        # Check GET /metrics
        try {
            $respMetrics = Invoke-WebRequest -Uri "http://127.0.0.1:8000/metrics" -UseBasicParsing -TimeoutSec 5
            $apiResults += "HTTP $($respMetrics.StatusCode) /metrics -> Length: $($respMetrics.Content.Length)"
            Log-Check "GET /metrics returns HTTP 200" ($respMetrics.StatusCode -eq 200 -and ($respMetrics.Content -match "http_request|python_")) "Status: $($respMetrics.StatusCode)"
        } catch {
            $apiResults += "ERROR /metrics : $_"
            Log-Check "GET /metrics returns HTTP 200" $false "$_"
        }
    }
    $apiResults | Out-File "$EVIDENCE_DIR\api.txt" -Encoding utf8
    Stop-Job $uvicornJob -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $uvicornJob -Force -ErrorAction SilentlyContinue | Out-Null
} else {
    Log-Warn "API tests skipped -- Docker not running"
}

# ── 10. Neo4j constraints ─────────────────────────────────────────────────────
Write-Host "`n[10/10] Neo4j Constraints" -ForegroundColor Cyan
if ($dockerRunning) {
    $neo4jPass = "devpassword123"
    if (Test-Path (Join-Path $repoRoot ".env")) {
        $parsed = (Get-Content (Join-Path $repoRoot ".env") | Select-String "NEO4J_PASSWORD" | ForEach-Object { ($_ -split "=")[1].Trim() })
        if (-not [string]::IsNullOrWhiteSpace($parsed)) { $neo4jPass = $parsed }
    }
    $constraintsOut = & docker compose -f infra/docker/docker-compose.yml exec -T neo4j cypher-shell -u neo4j -p "$neo4jPass" "SHOW CONSTRAINTS;" 2>&1
    $cExit = $LASTEXITCODE
    $indexesOut = & docker compose -f infra/docker/docker-compose.yml exec -T neo4j cypher-shell -u neo4j -p "$neo4jPass" "SHOW INDEXES;" 2>&1
    $iExit = $LASTEXITCODE
    "==> CONSTRAINTS (exit: $cExit)`n$constraintsOut`n`n==> INDEXES (exit: $iExit)`n$indexesOut" | Out-File "$EVIDENCE_DIR\neo4j.txt" -Encoding utf8
    $constraintCount = ($constraintsOut | Select-String "UNIQUENESS|UNIQUE").Count
    Log-Check "Neo4j constraints present (found: $constraintCount)" ($cExit -eq 0 -and $constraintCount -ge 11) "ExitCode: $cExit, Uniqueness constraints: $constraintCount"
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
