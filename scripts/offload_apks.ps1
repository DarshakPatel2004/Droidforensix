# Offload clutter sample sets out of samples/ into _offload/ (git-ignored).
# Scope (user-approved): malware: fresh_mb, random23_extracted, loose root *.apk/*.zip,
#                        modern_eval  |  goodware: benign_eval
param([switch]$DryRun)

$ErrorActionPreference = 'Stop'
$root = 'D:\DroidForensix'
$srcMal = Join-Path $root 'samples\malware'
$srcGood = Join-Path $root 'samples\goodware'
$dest = Join-Path $root '_offload'
$manifest = Join-Path $dest 'offload_manifest_2026-10-06.csv'

$hashCsv = 'C:\Users\darsh\AppData\Local\Temp\opencode\apk_hash_inventory.csv'
$hashByPath = @{}
if (Test-Path $hashCsv) {
  Import-Csv $hashCsv | ForEach-Object { $hashByPath[$_.Path] = $_.Hash }
}

# Moves: source dir -> dest dir (whole folder), or source file glob -> dest dir
$folderMoves = @(
  @{ src = Join-Path $srcMal 'fresh_mb';            dst = Join-Path $dest 'malware\fresh_mb' },
  @{ src = Join-Path $srcMal 'random23_extracted';  dst = Join-Path $dest 'malware\random23_extracted' },
  @{ src = Join-Path $srcMal 'modern_eval';         dst = Join-Path $dest 'malware\modern_eval' },
  @{ src = Join-Path $srcGood 'benign_eval';        dst = Join-Path $dest 'goodware\benign_eval' }
)
$looseApkDst = Join-Path $dest 'malware\loose_root_apks'
$looseZipDst = Join-Path $dest 'malware\random23_source_zips'

$rows = [System.Collections.Generic.List[object]]::new()
function Add-Row($old, $new) {
  $item = Get-Item -LiteralPath $new
  $rows.Add([pscustomobject]@{
    OldPath = $old; NewPath = $new
    Size = if ($item.PSIsContainer) { (Get-ChildItem -LiteralPath $new -Recurse -File | Measure-Object Length -Sum).Sum } else { $item.Length }
    Sha256 = if ($item.PSIsContainer) { '' } else { if ($hashByPath.ContainsKey($old)) { $hashByPath[$old] } else { (Get-FileHash -LiteralPath $new -Algorithm SHA256).Hash.ToLower() } }
  })
}

if ($DryRun) {
  $folderMoves | ForEach-Object { "MOVE DIR: $($_.src) -> $($_.dst)" }
  "MOVE FILES: $srcMal\*.apk -> $looseApkDst ($(( Get-ChildItem $srcMal -File -Filter *.apk).Count) files)"
  "MOVE FILES: $srcMal\*.zip -> $looseZipDst ($(( Get-ChildItem $srcMal -File -Filter *.zip).Count) files)"
  exit 0
}

New-Item -ItemType Directory -Force -Path $dest, $looseApkDst, $looseZipDst | Out-Null

# The manifest is written even if a move fails part-way, so moved files can always be located.
try {
  foreach ($m in $folderMoves) {
    if (-not (Test-Path $m.src)) { Write-Warning "skip missing $($m.src)"; continue }
    if (Test-Path $m.dst) { Write-Warning "skip, destination exists: $($m.dst)"; continue }
    New-Item -ItemType Directory -Force -Path (Split-Path $m.dst) | Out-Null
    Move-Item -LiteralPath $m.src -Destination $m.dst
    Add-Row $m.src $m.dst
    Write-Host "moved dir: $($m.src)"
  }

  foreach ($f in (Get-ChildItem $srcMal -File -Filter *.apk)) {
    $target = Join-Path $looseApkDst $f.Name
    if (Test-Path $target) { Write-Warning "skip, destination exists: $target"; continue }
    Move-Item -LiteralPath $f.FullName -Destination $target
    Add-Row $f.FullName $target
  }
  foreach ($f in (Get-ChildItem $srcMal -File -Filter *.zip)) {
    $target = Join-Path $looseZipDst $f.Name
    if (Test-Path $target) { Write-Warning "skip, destination exists: $target"; continue }
    Move-Item -LiteralPath $f.FullName -Destination $target
    Add-Row $f.FullName $target
  }
} finally {
  $rows | Export-Csv -NoTypeInformation -Path $manifest
}
Write-Host "manifest: $manifest ($($rows.Count) entries, $([math]::Round((($rows | Measure-Object Size -Sum).Sum)/1GB,2)) GB)"

# Report post-state
Write-Host "`n=== samples/ after offload ==="
Get-ChildItem $srcMal -Directory | ForEach-Object {
  $a = (Get-ChildItem $_.FullName -Recurse -File -Filter *.apk -ErrorAction SilentlyContinue).Count
  $z = (Get-ChildItem $_.FullName -Recurse -File -Filter *.zip -ErrorAction SilentlyContinue).Count
  "{0,-18} apk={1,-4} zip={2}" -f $_.Name, $a, $z
}
$rootApk = (Get-ChildItem $srcMal -File -Filter *.apk).Count
$rootZip = (Get-ChildItem $srcMal -File -Filter *.zip).Count
"{0,-18} apk={1,-4} zip={2}" -f '(root loose)', $rootApk, $rootZip
Get-ChildItem $srcGood -Directory | ForEach-Object {
  $a = (Get-ChildItem $_.FullName -Recurse -File -Filter *.apk -ErrorAction SilentlyContinue).Count
  "{0,-18} apk={1}" -f $_.Name, $a
}
