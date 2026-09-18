Write-Host "=== Phase 1: Delete Massive Artifacts ===" -ForegroundColor Cyan

Write-Host "  Deleting evaluation/ (decompiled APK artifacts)..." -NoNewline
if (Test-Path -LiteralPath "D:\DroidForensix\evaluation") {
    Remove-Item -LiteralPath "D:\DroidForensix\evaluation" -Recurse -Force
    Write-Host " DONE" -ForegroundColor Green
} else { Write-Host " SKIP (not found)" -ForegroundColor Yellow }

Write-Host "  Deleting IDE config folders..." -NoNewline
@('.superpowers', '.worktrees', '.agents', '.claude', '.gemini', '.code-review-graph') | ForEach-Object {
    $p = "D:\DroidForensix\$_"
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
}
Write-Host " DONE" -ForegroundColor Green

Write-Host "  Deleting __pycache__ folders..." -NoNewline
Get-ChildItem -Path D:\DroidForensix -Recurse -Directory -Filter __pycache__ -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -LiteralPath $_.FullName -Recurse -Force
}
Write-Host " DONE" -ForegroundColor Green

Write-Host "=== Phase 2: Delete Stale Root Docs ===" -ForegroundColor Cyan
@(
    'api-map.md', 'routes.md', 'database-map.md', 'dependency-graph.md',
    'API_SPEC.md', 'architecture.md', 'codebase_memory.md',
    'DARK_THEME_CHANGESET.md', 'FAILURE_ANALYSIS.md', 'SS_ANALYSIS.md',
    'EVALUATION.md', 'JADX_SETUP.md', 'upload-resilience-spec.md',
    '.windsurfrules', '.mcp.json', '.claudeconfig.json'
) | ForEach-Object {
    $p = "D:\DroidForensix\$_"
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

Write-Host "=== Phase 3: Delete Obsolete Plans ===" -ForegroundColor Cyan
@(
    'DroidForensix_Final_Draft.md',
    'DROIDFORENSIX_IMPLEMENTATION_PLAN.md',
    'SAMPLE_SOURCES.md',
    'identification_summary.md'
) | ForEach-Object {
    $p = "D:\DroidForensix\$_"
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

Write-Host "=== Phase 4: Delete One-Off Scripts ===" -ForegroundColor Cyan
@('check_hydra.py', 'ocr_extract.py', 'droidforensix_llm.py', '_map_errors.py') | ForEach-Object {
    $p = "D:\DroidForensix\$_"
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

Write-Host "=== Phase 5: Delete Old Ground Truth ===" -ForegroundColor Cyan
@(
    'ground_truth_fdroid.json', 'ground_truth_fdroid_existing.json',
    'ground_truth_drebin.json', 'ground_truth_test_set.json'
) | ForEach-Object {
    $p = "D:\DroidForensix\$_"
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

Write-Host "=== Phase 6: Delete Duplicate Backend Files ===" -ForegroundColor Cyan
if (Test-Path -LiteralPath "D:\DroidForensix\backend\threat_intelligence.py") { Remove-Item -LiteralPath "D:\DroidForensix\backend\threat_intelligence.py" -Force }
if (Test-Path -LiteralPath "D:\DroidForensix\backend\pdf_report.py") { Remove-Item -LiteralPath "D:\DroidForensix\backend\pdf_report.py" -Force }

Write-Host ""
Write-Host "=== Cleanup Complete ===" -ForegroundColor Green
