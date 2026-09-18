@echo off
REM ============================================================================
REM DroidForensix Backend Startup Script (Windows)
REM ============================================================================
REM 
REM This script:
REM 1. Navigates to the backend directory
REM 2. Starts the FastAPI server (which auto-starts Ollama if needed)
REM
REM Requirements:
REM - Python 3.10+ in PATH
REM - Ollama installed (https://ollama.ai) and in PATH
REM - FastAPI, uvicorn installed (pip install -r requirements.txt)
REM
REM Usage:
REM   start_backend.bat
REM
REM The backend will auto-detect and start Ollama on first request.
REM ============================================================================

setlocal enabledelayedexpansion

echo ============================================================================
echo DroidForensix Backend Startup
echo ============================================================================
echo.

REM Detect current script directory
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH
    echo Install Python 3.10+ or add it to PATH
    echo.
    pause
    exit /b 1
)

REM Navigate to backend
if exist "backend" (
    cd /d "backend"
) else if exist "main.py" (
    REM Already in backend directory
) else (
    echo [ERROR] Can't find backend directory
    echo Run this script from the DroidForensix root, or create a symlink from backend
    echo.
    pause
    exit /b 1
)

echo.
echo Starting FastAPI backend on http://localhost:8000
echo [INFO] Ollama will auto-start if not already running
echo [INFO] First request may take 10-15s (Ollama startup)
echo.
echo Press Ctrl+C to stop the backend
echo ============================================================================
echo.

REM Start the backend with auto-reload for development
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

pause