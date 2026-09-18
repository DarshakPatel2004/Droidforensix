param(
    [Parameter(Mandatory = $false)]
    [string]$VmName = "Android-Malware-Analysis",

    [Parameter(Mandatory = $false)]
    [string]$VmPath = "$env:USERPROFILE\Documents\Virtual Machines\$VmName",

    [Parameter(Mandatory = $false)]
    [string]$IsoPath = "$env:USERPROFILE\Downloads\android-x86_64-9.0-r2.iso",

    [Parameter(Mandatory = $false)]
    [string]$IsoUrl = "https://sourceforge.net/projects/android-x86/files/Release%209.0/android-x86_64-9.0-r2.iso/download",

    [Parameter(Mandatory = $false)]
    [int]$RamMB = 4096,

    [Parameter(Mandatory = $false)]
    [int]$Cores = 2,

    [Parameter(Mandatory = $false)]
    [int]$DiskGB = 32,

    [Parameter(Mandatory = $false)]
    [switch]$DownloadOnly
)

$ErrorActionPreference = "Stop"
$VmwarePath = "C:\Program Files (x86)\VMware\VMware Workstation"

function Write-Step {
    param([string]$Message)
    Write-Host ">>> $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "WARNING: $Message" -ForegroundColor Yellow
}

function Write-Ok {
    param([string]$Message)
    Write-Host "OK: $Message" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 1. Check prerequisites
# ---------------------------------------------------------------------------
Write-Step "Checking prerequisites..."

$vmrun = Join-Path $VmwarePath "vmrun.exe"
$vdiskman = Join-Path $VmwarePath "vmware-vdiskmanager.exe"
if (-not (Test-Path $vmrun)) {
    throw "VMware Workstation not found at $VmwarePath. Install it first."
}
Write-Ok "Found vmrun at $vmrun"

if (-not (Test-Path $vdiskman)) {
    throw "vmware-vdiskmanager.exe not found alongside vmrun."
}
Write-Ok "Found vdiskmanager at $vdiskman"

# ---------------------------------------------------------------------------
# 2. Download ISO if needed
# ---------------------------------------------------------------------------
if (-not (Test-Path $IsoPath)) {
    Write-Step "Downloading Android-x86 9.0 ISO (~965 MB) to $IsoPath ..."
    $isoDir = Split-Path $IsoPath -Parent
    if (-not (Test-Path $isoDir)) {
        New-Item -ItemType Directory -Path $isoDir -Force | Out-Null
    }

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        Register-ObjectEvent -InputObject $wc -EventName DownloadProgressChanged -Action {
            $pct = $eventArgs.ProgressPercentage
            $received = $eventArgs.BytesReceived / 1MB
            $total = $eventArgs.TotalBytesToReceive / 1MB
            Write-Progress -Activity "Downloading Android-x86 ISO" -Status "$([math]::Round($received,1)) MB / $([math]::Round($total,1)) MB" -PercentComplete $pct
        } | Out-Null
        $wc.DownloadFileAsync($IsoUrl, $IsoPath)
        while ($wc.IsBusy) { Start-Sleep -Seconds 1 }
        Write-Progress -Activity "Downloading Android-x86 ISO" -Completed
        Unregister-Event -SourceIdentifier * -ErrorAction SilentlyContinue
    }
    catch {
        # fallback: BITS transfer
        Write-Warn "WebClient failed, trying BITS transfer..."
        Start-BitsTransfer -Source $IsoUrl -Destination $IsoPath -DisplayName "Android-x86 ISO" -Priority High
    }

    if (-not (Test-Path $IsoPath)) {
        throw "Download failed. Try manually from $IsoUrl"
    }
    Write-Ok "Downloaded $( '{0:N1}' -f ((Get-Item $IsoPath).Length / 1MB) ) MB"
}
else {
    Write-Ok "ISO already present at $IsoPath"
}

if ($DownloadOnly) {
    Write-Step "Download complete. Exiting (DownloadOnly flag set)."
    return
}

# ---------------------------------------------------------------------------
# 3. Create VM directory
# ---------------------------------------------------------------------------
Write-Step "Creating VM at $VmPath ..."
if (Test-Path $VmPath) {
    throw "Directory $VmPath already exists. Remove it or choose a different VmName."
}
New-Item -ItemType Directory -Path $VmPath -Force | Out-Null

$vmxFile = Join-Path $VmPath "$VmName.vmx"
$vmdkFile = Join-Path $VmPath "$VmName.vmdk"

# ---------------------------------------------------------------------------
# 4. Create virtual disk
# ---------------------------------------------------------------------------
Write-Step "Creating $DiskGB GB virtual disk (split into 2GB files)..."
& $vdiskman -c -t 1 -s "${DiskGB}GB" -a lsilogic "$vmdkFile" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "vdiskman failed with exit code $LASTEXITCODE"
}
Write-Ok "Virtual disk created"

# ---------------------------------------------------------------------------
# 5. Generate .vmx config (hardened for malware analysis)
# ---------------------------------------------------------------------------
Write-Step "Writing VMX configuration..."

$vmxContent = @"
.encoding = "windows-1252"
config.version = "8"
virtualHW.version = "21"

# Guest OS
guestOS = "otherlinux-64"
vmci0.present = "TRUE"

# Display name
displayName = "$VmName"
annotation = "ANDROID MALWARE ANALYSIS VM - DO NOT CONNECT TO HOST NETWORK WITHOUT PROXY"

# CPU
numvcpus = "$Cores"
cpuid.coresPerSocket = "1"
memsize = "$RamMB"

# SATA controller (for ISO)
sata0.present = "TRUE"
sata0.autodetect = "TRUE"

# IDE disk (Android-x86 prefers IDE over SATA)
ide0:0.present = "TRUE"
ide0:0.fileName = "$vmdkFile"
ide0:0.deviceType = "disk"
ide0:0.writeThrough = "TRUE"

# IDE CDROM (Android-x86 ISO)
ide1:0.present = "TRUE"
ide1:0.fileName = "$IsoPath"
ide1:0.deviceType = "cdrom-image"
ide1:0.startConnected = "TRUE"

# Network adapter - NAT only
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
ethernet0.virtualDev = "e1000"
ethernet0.allowGuestConnectionControl = "FALSE"
ethernet0.startConnected = "TRUE"
ethernet0.addressType = "generated"

# NO USB controllers (attack surface reduction)
usb.present = "FALSE"
usb.vbluetooth.startConnected = "FALSE"
ehci.present = "FALSE"
xhci.present = "FALSE"

# NO sound
sound.present = "FALSE"

# NO printer
serial0.present = "FALSE"
parallel0.present = "FALSE"

# NO shared folders
isolation.tools.hgfs.disable = "TRUE"
sharedFolder.maxNum = "0"
sharedFolder0.present = "FALSE"

# Isolation lockdown
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
isolation.tools.drag.disable = "TRUE"
isolation.tools.setGUIOptions.enable = "FALSE"
isolation.tools.dnshostlookup.disable = "TRUE"
isolation.tools.diskShrink.enable = "FALSE"
isolation.tools.diskWiper.enable = "FALSE"
isolation.tools.ghi.autologon.disable = "TRUE"

# Disable 3D acceleration (not needed, reduces attack surface)
svga.autodetect = "FALSE"
mks.enable3d = "FALSE"
svga.vramSize = "16777216"

# Disable guest-initiated power ops
isolation.tools.unity.disable = "TRUE"
isolation.tools.unityInterlockOperation.disable = "TRUE"
isolation.tools.unity.taskbar.disable = "TRUE"
isolation.tools.unity.sync.disable = "TRUE"
isolation.tools.unityActive.disable = "TRUE"
isolation.tools.unity.windowContents.disable = "TRUE"

# Disable time sync (avoid suspicious clock jumps to host time)
tools.syncTime = "FALSE"
tools.syncTime.allowSetTime = "FALSE"
tools.syncTime.allowPowerManagement = "FALSE"

# Disable auto-upgrade of VMware tools (prevents unwanted host communication)
tools.upgrade.policy = "manual"
tools.capability.upgrade = "FALSE"

# Debug off (some malware checks for VMware debug mode)
debug = "FALSE"

# Power management off
powerType.powerOff = "soft"
powerType.suspend = "soft"
powerType.reset = "soft"

# Floppy (remove)
floppy0.present = "FALSE"

# Logging minimal
log.fileName = "$VmName.log"
log.append = "TRUE"
log.rotateSize = "1048576"
"@

Set-Content -Path $vmxFile -Value $vmxContent -Encoding Ascii
Write-Ok "VMX configuration written"

# ---------------------------------------------------------------------------
# 6. Register VM with VMware
# ---------------------------------------------------------------------------
Write-Step "Registering VM with VMware Workstation..."
& $vmrun -T ws register "$vmxFile" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Registration failed (exit $LASTEXITCODE). You can register manually: File -> Open -> $vmxFile"
}
else {
    Write-Ok "VM registered"
}

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  ANDROID MALWARE ANALYSIS VM CREATED" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Name:       $VmName" -ForegroundColor White
Write-Host "  Path:       $VmPath" -ForegroundColor White
Write-Host "  RAM:        $RamMB MB" -ForegroundColor White
Write-Host "  CPU:        $Cores cores" -ForegroundColor White
Write-Host "  Disk:       $DiskGB GB" -ForegroundColor White
Write-Host "  ISO:        $IsoPath" -ForegroundColor White
Write-Host ""
Write-Host "  VMX:        $vmxFile" -ForegroundColor White
Write-Host ""
Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Open VMware Workstation -> Start the VM" -ForegroundColor Yellow
Write-Host "  2. Install Android-x86 (choose the ISO at boot)" -ForegroundColor Yellow
Write-Host "  3. After install, remove ISO and reboot" -ForegroundColor Yellow
Write-Host "  4. Take a 'Clean Base' snapshot" -ForegroundColor Yellow
Write-Host "  5. Install mitmproxy CA cert (see below)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ON HOST: mitmproxy --listen-port 8888" -ForegroundColor Yellow
Write-Host "  IN VM:   Settings -> WiFi -> Proxy -> Manual" -ForegroundColor Yellow
Write-Host "           Host: 192.168.x.1  Port: 8888" -ForegroundColor Yellow
Write-Host "           (Find x via Edit -> Virtual Network Editor -> VMnet8)" -ForegroundColor Yellow
Write-Host "  Then browse to mitm.it to install CA cert" -ForegroundColor Yellow
Write-Host ""
Write-Host "  SNAPSHOT CMDS:" -ForegroundColor Yellow
Write-Host "    vmrun -T ws snapshot `"$vmxFile`" Clean-Base" -ForegroundColor Gray
Write-Host "    vmrun -T ws revertToSnapshot `"$vmxFile`" Clean-Base" -ForegroundColor Gray
Write-Host ""

if ((Get-Item $IsoPath).Length -gt 900MB) {
    Write-Ok "ISO downloaded and ready"
}
