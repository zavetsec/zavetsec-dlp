﻿#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Mass deployment of ZavetSec DLP Agent via WinRM.

.PARAMETER Computers
    List of target machine names or IPs.

.PARAMETER ServerUrl
    DLP server URL. Example: https://192.168.1.100:5001

.PARAMETER ApiKey
    API key from server appsettings.json.

.PARAMETER SourceDir
    Path to agent publish\ folder. Default: script directory.

.PARAMETER InstallDir
    Install directory on target machines. Default: C:\ProgramData\ZavetSec\Agent

.PARAMETER ConcurrentJobs
    Number of parallel jobs. Default: 10.

.PARAMETER Credential
    PSCredential for remote connection. Uses current credentials if not specified.

.EXAMPLE
    .\deploy.ps1 -Computers "PC-01","PC-02" -ServerUrl "https://dlp.co:5001" -ApiKey "key"

.EXAMPLE
    .\deploy.ps1 -Computers (Get-Content .\machines.txt) -ServerUrl "https://dlp.co:5001" -ApiKey "key"

.EXAMPLE
    $pcs = (Get-ADComputer -Filter * -SearchBase "OU=Work,DC=company,DC=local").Name
    .\deploy.ps1 -Computers $pcs -ServerUrl "https://dlp.co:5001" -ApiKey "key" -ConcurrentJobs 20
#>
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Computers,

    [Parameter(Mandatory=$true)]
    [string]$ServerUrl,

    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

    [string]$SourceDir = $PSScriptRoot,

    [string]$InstallDir = "C:\ProgramData\ZavetSec\Agent",

    [int]$ConcurrentJobs = 10,

    [PSCredential]$Credential
)

$ErrorActionPreference = "Continue"
$AgentExe = "ZavetSecDlpAgent.exe"

# Find publish folder
$publishDir = $SourceDir
if (-not (Test-Path "$publishDir\$AgentExe")) {
    $publishDir = Join-Path $SourceDir "publish"
}
if (-not (Test-Path "$publishDir\$AgentExe")) {
    Write-Error "Cannot find $AgentExe in $SourceDir or $SourceDir\publish\"
    exit 1
}

Write-Host ""
Write-Host "=== ZavetSec DLP Mass Deployment ===" -ForegroundColor Cyan
Write-Host "Machines   : $($Computers.Count)"
Write-Host "Server     : $ServerUrl"
Write-Host "Source     : $publishDir"
Write-Host "Concurrent : $ConcurrentJobs"
Write-Host ""

# Concurrent results bag
$results   = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$startTime = Get-Date

# Build config JSON (no Cyrillic)
$sensitiveWords = @("password","passwd","secret","token","private key","confidential","credit","ssn")

$configObj = [ordered]@{
    screenshot = [ordered]@{
        intervalMinutes=5; jpegQuality=75; onWindowChange=$true
        onStartup=$true; windowCheckIntervalSeconds=1; blankScreenDetection=$true
    }
    keylogger = [ordered]@{ enabled=$true; bufferChars=512; flushSeconds=30 }
    clipboard = [ordered]@{
        enabled=$true; pollIntervalMs=500; maxContentLength=4096
        sensitiveWords=$sensitiveWords
    }
    network = [ordered]@{
        enabled=$true; connectionCheckSeconds=10; dnsCheckSeconds=30
        alertPorts=@(22,23,3389,4444,5900,6667)
    }
    storage = [ordered]@{
        logDir="C:\ProgramData\ZavetSec\DLP\Logs"
        screenshotDir="C:\ProgramData\ZavetSec\DLP\Screenshots"
        keyFile="C:\ProgramData\ZavetSec\DLP\agent.key"
        retentionLogDays=30; retentionScreenshotDays=7
        maxLogMb=500; maxScreenshotMb=2048
    }
    processes = [ordered]@{
        enabled=$true; checkIntervalSeconds=10
        whitelist=@("svchost","csrss","lsass","explorer","dwm","winlogon")
        suspiciousProcesses=@("mimikatz","wireshark","nc","nmap","psexec","procdump")
    }
    screenshotEncrypt = [ordered]@{ enabled=$true }
    shipper = [ordered]@{
        enabled=$true; serverUrl=$ServerUrl; apiKey=$ApiKey
        batchSize=50; flushSeconds=30; maxQueueSize=5000
        deleteLocalScreenshotsAfterUpload=$true; allowInvalidCertificate=$true
    }
}
$configJson = $configObj | ConvertTo-Json -Depth 10

# Remote script block
$remoteBlock = {
    param($Dir, $Exe, $Json)
    try {
        Get-Process -Name "ZavetSecDlpAgent" -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
        Start-Sleep -Milliseconds 500
        schtasks /delete /tn "ZavetSec DLP Agent"      /f 2>$null | Out-Null
        schtasks /delete /tn "ZavetSec DLP Agent Boot" /f 2>$null | Out-Null
        Add-MpPreference -ExclusionPath    $Dir                         -EA SilentlyContinue
        Add-MpPreference -ExclusionPath    "C:\ProgramData\ZavetSec\DLP" -EA SilentlyContinue
        Add-MpPreference -ExclusionProcess $Exe                          -EA SilentlyContinue
        if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
        $Json | Set-Content -Path (Join-Path $Dir "config.json") -Encoding UTF8
        $ep = "`"$(Join-Path $Dir $Exe)`" --task-mode"
        schtasks /create /tn "ZavetSec DLP Agent"      /tr $ep /sc ONLOGON /ru SYSTEM /rl HIGHEST /f | Out-Null
        schtasks /create /tn "ZavetSec DLP Agent Boot" /tr $ep /sc ONSTART /ru SYSTEM /rl HIGHEST /f | Out-Null
        schtasks /run /tn "ZavetSec DLP Agent" | Out-Null
        Start-Sleep -Seconds 3
        $pid2 = (Get-Process -Name "ZavetSecDlpAgent" -EA SilentlyContinue)?.Id
        return @{ Success=$true; Message="OK PID=$pid2" }
    } catch {
        return @{ Success=$false; Message=$_.Exception.Message }
    }
}

# Parallel execution
$sem  = [System.Threading.SemaphoreSlim]::new($ConcurrentJobs, $ConcurrentJobs)
$jobs = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()

foreach ($computer in $Computers) {
    $sem.Wait()
    $c = $computer.Trim()
    if ([string]::IsNullOrWhiteSpace($c)) { $sem.Release(); continue }

    $task = [System.Threading.Tasks.Task]::Run({
        try {
            if (-not (Test-Connection -ComputerName $c -Count 1 -Quiet -EA SilentlyContinue)) {
                Write-Host "  [SKIP] $c - unreachable" -ForegroundColor Yellow
                $results.Add([pscustomobject]@{Computer=$c;Status="SKIP";Message="Unreachable"})
                return
            }
            $dest = "\$c" + $InstallDir.Replace(":", "$")
            if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
            Copy-Item -Path "$publishDir\*" -Destination $dest -Recurse -Force -EA Stop

            $sp = @{ ComputerName=$c; ScriptBlock=$remoteBlock; ArgumentList=$InstallDir,$AgentExe,$configJson }
            if ($Credential) { $sp.Credential = $Credential }
            $r = Invoke-Command @sp -EA Stop

            if ($r.Success) {
                Write-Host "  [OK]   $c - $($r.Message)" -ForegroundColor Green
                $results.Add([pscustomobject]@{Computer=$c;Status="OK";Message=$r.Message})
            } else {
                Write-Host "  [FAIL] $c - $($r.Message)" -ForegroundColor Red
                $results.Add([pscustomobject]@{Computer=$c;Status="FAIL";Message=$r.Message})
            }
        } catch {
            Write-Host "  [FAIL] $c - $_" -ForegroundColor Red
            $results.Add([pscustomobject]@{Computer=$c;Status="FAIL";Message=$_.Exception.Message})
        } finally {
            $sem.Release()
        }
    }.GetAwaiter())
    $jobs.Add($task)
}

[System.Threading.Tasks.Task]::WaitAll($jobs.ToArray())

$elapsed = [int]((Get-Date) - $startTime).TotalSeconds
$ok   = ($results | Where-Object { $_.Status -eq "OK"   }).Count
$fail = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$skip = ($results | Where-Object { $_.Status -eq "SKIP" }).Count

Write-Host ""
Write-Host "=== Deployment complete (${elapsed}s) ===" -ForegroundColor Cyan
Write-Host "Success : $ok"  -ForegroundColor Green
if ($fail -gt 0) { Write-Host "Failed  : $fail" -ForegroundColor Red }
if ($skip -gt 0) { Write-Host "Skipped : $skip" -ForegroundColor Yellow }

$reportPath = Join-Path $PSScriptRoot "deploy_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $reportPath -Encoding UTF8 -NoTypeInformation
Write-Host "Report  : $reportPath" -ForegroundColor Cyan
