@echo off
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    .\.venv\Scripts\python.exe scripts\stop_local.py %*
) else (
    python scripts\stop_local.py %*
)
