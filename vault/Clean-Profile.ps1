# Nuclear Profile Fix - Delete and Recreate
# This deletes your current profile and creates a clean one
# Usage: powershell -ExecutionPolicy Bypass -File Clean-Profile.ps1

$profilePath = $PROFILE

Write-Host "PowerShell Profile Fix" -ForegroundColor Blue
Write-Host "=====================" -ForegroundColor Blue
Write-Host ""
Write-Host "Current profile: $profilePath" -ForegroundColor Cyan
Write-Host ""

# Backup old profile just in case
if (Test-Path $profilePath) {
    $backupPath = "$profilePath.backup"
    Copy-Item -Path $profilePath -Destination $backupPath -Force
    Write-Host "[OK] Backed up to: $backupPath" -ForegroundColor Green
    
    Remove-Item -Path $profilePath -Force
    Write-Host "[OK] Deleted old profile" -ForegroundColor Green
}

# Create profile directory
$profileDir = Split-Path -Parent $profilePath
if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    Write-Host "[OK] Created profile directory" -ForegroundColor Green
}

# Create fresh clean profile
$vaultPath = "$env:USERPROFILE\OneDrive\Documents\my-forensics-vault"
$contextScript = "$env:USERPROFILE\OneDrive\Documents\Inject-Context.ts"

$cleanProfile = "# OpenCode + Obsidian Vault Integration`n`n`$env:OBSIDIAN_VAULT = `"$vaultPath`"`n`nfunction Invoke-OpenCodeBrain {`n    param([Parameter(ValueFromRemainingArguments=`$true)][string[]]`$Arguments)`n    `n    try {`n        `$tempFile = [System.IO.Path]::GetTempFileName()`n        & node --experimental-strip-types `"$contextScript`" | Out-File -FilePath `$tempFile -Encoding UTF8`n        `$context = Get-Content -Path `$tempFile -Raw`n        Remove-Item -Path `$tempFile -Force`n        `n        if (`$context) {`n            & opencode --system `"`$context`" @Arguments`n        } else {`n            & opencode @Arguments`n        }`n    } catch {`n        & opencode @Arguments`n    }`n}`n`nSet-Alias -Name oc -Value Invoke-OpenCodeBrain -Force`n"

$cleanProfile | Out-File -FilePath $profilePath -Encoding UTF8 -Force
Write-Host "[OK] Created fresh profile" -ForegroundColor Green

Write-Host ""
Write-Host "Now reload PowerShell by running:" -ForegroundColor White
Write-Host ""
Write-Host "  . `$PROFILE" -ForegroundColor Cyan
Write-Host ""
Write-Host "Then test:" -ForegroundColor White
Write-Host ""
Write-Host "  oc" -ForegroundColor Cyan
Write-Host ""
