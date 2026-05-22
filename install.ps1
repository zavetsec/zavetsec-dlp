#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs ZavetSec DLP Agent on the local machine.

.PARAMETER ServerUrl
    DLP server URL. Example: https://192.168.1.100:5001

.PARAMETER ApiKey
    API key from server appsettings.json.

.PARAMETER InstallDir
    Agent install directory. Default: C:\ProgramData\ZavetSec\Agent

.PARAMETER SourceDir
    Path to agent publish\ folder. Default: script directory.

.EXAMPLE
    .\install.ps1 -ServerUrl "https://192.168.1.100:5001" -ApiKey "mykey123"
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,

    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

    [string]$InstallDir = "C:\ProgramData\ZavetSec\Agent",

    [string]$SourceDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"
$AgentExe  = "ZavetSecDlpAgent.exe"
$TaskName1 = "ZavetSec DLP Agent"
$TaskName2 = "ZavetSec DLP Agent Boot"

Write-Host ""
Write-Host "=== ZavetSec DLP Agent Installer ===" -ForegroundColor Cyan
Write-Host "Server  : $ServerUrl"
Write-Host "Install : $InstallDir"
Write-Host ""

# --- Find publish folder ---
$publishDir = $SourceDir
if (-not (Test-Path "$publishDir\$AgentExe")) {
    $publishDir = Join-Path $SourceDir "publish"
}
if (-not (Test-Path "$publishDir\$AgentExe")) {
    Write-Error "Cannot find $AgentExe in $SourceDir or $SourceDir\publish\"
    exit 1
}
Write-Host "[1/6] Source: $publishDir" -ForegroundColor Green

# --- Stop old agent if running ---
$proc = Get-Process -Name "ZavetSecDlpAgent" -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "[2/6] Stopping old agent (PID=$($proc.Id))..." -ForegroundColor Yellow
    $proc | Stop-Process -Force
    Start-Sleep -Seconds 2
} else {
    Write-Host "[2/6] Agent not running" -ForegroundColor Green
}

foreach ($tn in @($TaskName1, $TaskName2)) {
    try { $null = & schtasks /delete /tn $tn /f 2>&1 } catch { }
}

# --- Add Windows Defender exclusion ---
Write-Host "[3/6] Adding Windows Defender exclusion..." -ForegroundColor Green
try {
    Add-MpPreference -ExclusionPath    $InstallDir                   -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath    "C:\ProgramData\ZavetSec\DLP" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess $AgentExe                      -ErrorAction SilentlyContinue
    Write-Host "       Exclusion added" -ForegroundColor Green
} catch {
    Write-Warning "Could not add Defender exclusion: $_"
}

# --- Copy files ---
Write-Host "[4/6] Copying files to $InstallDir..." -ForegroundColor Green
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Copy-Item -Path "$publishDir\*" -Destination $InstallDir -Recurse -Force

# --- Create config.json ---
Write-Host "[5/6] Creating config.json..." -ForegroundColor Green

$sensitiveWords = @(
    "password", "passwd", "secret", "token",
    "private key", "confidential", "credit", "ssn"
)

$config = [ordered]@{
    screenshot = [ordered]@{
        intervalMinutes            = 5
        jpegQuality                = 75
        onWindowChange             = $true
        onStartup                  = $true
        windowCheckIntervalSeconds = 1
        blankScreenDetection       = $true
    }
    keylogger = [ordered]@{
        enabled      = $true
        bufferChars  = 512
        flushSeconds = 30
    }
    clipboard = [ordered]@{
        enabled          = $true
        pollIntervalMs   = 500
        maxContentLength = 4096
        sensitiveWords   = $sensitiveWords
    }
    network = [ordered]@{
        enabled                = $true
        connectionCheckSeconds = 10
        dnsCheckSeconds        = 30
        alertPorts             = @(22, 23, 3389, 4444, 5900, 6667)
    }
    storage = [ordered]@{
        logDir                  = "C:\ProgramData\ZavetSec\DLP\Logs"
        screenshotDir           = "C:\ProgramData\ZavetSec\DLP\Screenshots"
        keyFile                 = "C:\ProgramData\ZavetSec\DLP\agent.key"
        retentionLogDays        = 30
        retentionScreenshotDays = 7
        maxLogMb                = 500
        maxScreenshotMb         = 2048
    }
    processes = [ordered]@{
        enabled              = $true
        checkIntervalSeconds = 10
        whitelist            = @("svchost", "csrss", "lsass", "explorer", "dwm", "winlogon")
        suspiciousProcesses  = @("mimikatz", "wireshark", "nc", "nmap", "psexec", "procdump")
    }
    screenshotEncrypt = [ordered]@{ enabled = $true }
    shipper = [ordered]@{
        enabled                           = $true
        serverUrl                         = $ServerUrl
        apiKey                            = $ApiKey
        batchSize                         = 50
        flushSeconds                      = 30
        maxQueueSize                      = 5000
        deleteLocalScreenshotsAfterUpload = $true
        allowInvalidCertificate           = $true
    }
}

$configJson  = $config | ConvertTo-Json -Depth 10
$configPath  = Join-Path $InstallDir "config.json"
$configJson | Set-Content -Path $configPath -Encoding UTF8
Write-Host "       config.json created: $configPath" -ForegroundColor Green

# --- Scheduled tasks ---
Write-Host "[6/6] Registering scheduled tasks..." -ForegroundColor Green
$exePath = "`"$InstallDir\$AgentExe`" --task-mode"

# ONLOGON task runs as the logged-in user (required for screenshot access)
# /ru "" means "current interactive user" - gives access to desktop session
try { $null = & schtasks /create /tn $TaskName1 /tr $exePath /sc ONLOGON /rl HIGHEST /f 2>&1 } catch { }

# ONSTART boot persistence task runs as SYSTEM (no desktop needed, just starts on boot)
# It will re-launch correctly when user logs in via the ONLOGON task
try { $null = & schtasks /create /tn $TaskName2 /tr $exePath /sc ONSTART /ru SYSTEM /rl HIGHEST /f 2>&1 } catch { }

# Watchdog task — runs every 5 minutes as SYSTEM
# Restarts the agent if the process is not running (crash recovery)
$TaskNameWD = "ZavetSec DLP Watchdog"
$wdScript   = "if (!(Get-Process ZavetSecDlpAgent -ErrorAction SilentlyContinue)) { " +
              "Start-Process '$InstallDir\$AgentExe' -ArgumentList '--task-mode' }"
$wdCmd      = "powershell -WindowStyle Hidden -Command `"$wdScript`""
try { $null = & schtasks /create /tn $TaskNameWD /tr $wdCmd /sc MINUTE /mo 5 /ru SYSTEM /rl HIGHEST /f 2>&1 } catch { }

# Start immediately — launch directly since schtasks /run
# does not work for ONLOGON tasks in interactive sessions
Start-Process -FilePath "$InstallDir\$AgentExe" -ArgumentList "--task-mode" -WindowStyle Hidden
Start-Sleep -Seconds 3

# Verify
$running = Get-Process -Name "ZavetSecDlpAgent" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host ""
    Write-Host "=== Installation complete ===" -ForegroundColor Green
    Write-Host "Agent running (PID=$($running.Id))" -ForegroundColor Green
    Write-Host "Server: $ServerUrl" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Agent will appear in dashboard in ~30 seconds." -ForegroundColor Yellow
} else {
    Write-Warning "Agent did not start automatically."
    Write-Host "Start manually:"
    Write-Host "  schtasks /run /tn `"$TaskName1`""
}
