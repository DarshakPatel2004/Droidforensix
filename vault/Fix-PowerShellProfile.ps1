# Manual fix for PowerShell profile
# Run this in PowerShell to fix the alias

# Step 1: Remove the bad alias entry
Write-Host "Removing bad alias from profile..." -ForegroundColor Blue

$profilePath = $PROFILE
$profileContent = Get-Content -Path $profilePath -Raw

# Remove the problematic section (the one with 2>$null)
$profileContent = $profileContent -replace '(?s)function Invoke-OpenCodeBrain.*?Set-Alias.*?Force.*?\n', ''

# Save cleaned profile
$profileContent | Out-File -Path $profilePath -Encoding UTF8 -Force
Write-Host "[OK] Cleaned profile" -ForegroundColor Green

# Step 2: Add correct alias
Write-Host "Adding correct alias..." -ForegroundColor Blue

$vaultPath = "$env:USERPROFILE\OneDrive\Documents\my-forensics-vault"
$contextScript = "$env:USERPROFILE\OneDrive\Documents\Inject-Context.ts"

$correctAlias = @"

# ============================================
# OpenCode + Obsidian Vault Integration
# ============================================

`$env:OBSIDIAN_VAULT = "$vaultPath"

function Invoke-OpenCodeBrain {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments=`$true)]
        [string[]]`$Arguments
    )
    
    try {
        # Get context from Inject-Context.ts
        `$contextFile = [System.IO.Path]::GetTempFileName()
        node --experimental-strip-types "$contextScript" | Out-File -FilePath `$contextFile -Encoding UTF8 -ErrorAction SilentlyContinue
        
        `$vaultContext = Get-Content -Path `$contextFile -Raw -ErrorAction SilentlyContinue
        Remove-Item -Path `$contextFile -ErrorAction SilentlyContinue
        
        if (`$vaultContext -and `$vaultContext.Length -gt 0) {
            opencode --system "`$vaultContext" @Arguments
        } else {
            Write-Host "Warning: Could not inject vault context" -ForegroundColor Yellow
            opencode @Arguments
        }
    } catch {
        Write-Host "Error: `$_" -ForegroundColor Red
        opencode @Arguments
    }
}

Set-Alias -Name oc -Value Invoke-OpenCodeBrain -Force -Scope Global

"@

Add-Content -Path $profilePath -Value $correctAlias -Encoding UTF8
Write-Host "[OK] Added correct alias" -ForegroundColor Green

Write-Host ""
Write-Host "Now reload PowerShell:" -ForegroundColor White
Write-Host "  . `$PROFILE" -ForegroundColor Cyan
Write-Host ""
Write-Host "Then test:" -ForegroundColor White
Write-Host "  oc" -ForegroundColor Cyan
