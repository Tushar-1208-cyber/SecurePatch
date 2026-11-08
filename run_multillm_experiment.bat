@echo off
setlocal
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
  echo SecurePatch virtual environment not found.
  echo Run this file from the SecurePatch project root.
  pause
  exit /b 1
)
venv\Scripts\python.exe run_multillm_experiment.py --repo sample_repo --max-vulns 5
pause
