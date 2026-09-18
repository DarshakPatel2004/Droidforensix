@echo off
set "ROOT=%~dp0"
cd /d "%ROOT%frontend"

REM Use bundled Node/npm
set "PATH=%ROOT%tools\node\current;%PATH%"

if not exist package.json (
    echo package.json not found in frontend directory
    exit /b 1
)

if not exist node_modules (
    echo Installing frontend dependencies...
    call npm install
    if errorlevel 1 (
        echo npm install failed
        exit /b 1
    )
)

echo Starting Vite frontend dev server...
npm run dev
