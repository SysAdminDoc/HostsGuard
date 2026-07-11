<#
.SYNOPSIS
    Elevated interactive end-to-end harness (NET-182).

.DESCRIPTION
    Exercises the live paths the headless suite cannot: a real LocalSystem
    HostsGuardSvc, real Windows Firewall COM rules, the Security-audit-driven
    consent loop (5152/5157), and posture restore-on-stop.

    Phases:
      1. Preflight  - elevation, firewall profiles enabled, Filtering Platform
                      audit policy (enabled for the run, restored after).
      2. Service    - optionally install from -InstallerPath, else use the
                      installed HostsGuardSvc; must reach the pipe via the CLI.
      3. Rule write - block a scratch executable through the CLI and assert the
                      HG_ rule exists in the LIVE firewall (Get-NetFirewallRule),
                      then remove it.
      4. Consent    - arm Notify mode (default-outbound Block with prior saved),
                      make a synthetic outbound connection that gets dropped,
                      and assert the service's event ledger saw the consent path.
      5. Restore    - back to Normal mode (posture restored), then stop the
                      service and assert restore-on-stop; restart the service.

    Run this on an ELEVATED INTERACTIVE session of a host whose firewall is ON
    (the dedicated test VM). It intentionally refuses hosts with the firewall
    disabled rather than flipping a profile the operator turned off.

.PARAMETER InstallerPath
    Optional HostsGuard Setup exe; installed /VERYSILENT before the run.

.PARAMETER CliPath
    Path to HostsGuard.Cli.exe. Defaults to the installed location, falling
    back to the repo publish output.

.PARAMETER TimeoutSec
    How long to wait for the consent-path ledger evidence. Default 60.

.PARAMETER PreflightOnly
    Run phase 1 only and report whether this host can host the E2E.
#>
[CmdletBinding()]
param(
    [string]$InstallerPath = '',
    [string]$CliPath = '',
    [int]$TimeoutSec = 60,
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
$script:Failures = @()
$script:AuditWasEnabled = $null

function Write-Phase([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Pass([string]$Text) { Write-Host "  PASS  $Text" -ForegroundColor Green }
function Write-FailStep([string]$Text) {
    Write-Host "  FAIL  $Text" -ForegroundColor Red
    $script:Failures += $Text
}

function Resolve-Cli {
    if ($CliPath -and (Test-Path $CliPath)) { return (Resolve-Path $CliPath).Path }
    $candidates = @(
        (Join-Path ${env:ProgramFiles} 'HostsGuard\HostsGuard.Cli.exe'),
        (Join-Path $PSScriptRoot '..\dist\dotnet\win-x64\HostsGuard.Cli.exe'),
        (Join-Path $PSScriptRoot '..\src\HostsGuard.Cli\bin\Debug\net10.0-windows\HostsGuard.Cli.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    throw "HostsGuard.Cli.exe not found - pass -CliPath (looked in: $($candidates -join '; '))"
}

function Invoke-Cli {
    param([Parameter(Mandatory)][string[]]$CliArgs, [int]$ExpectExit = 0)
    $out = & $script:Cli @CliArgs 2>&1 | Out-String
    if ($LASTEXITCODE -ne $ExpectExit) {
        throw "CLI $($CliArgs -join ' ') exited $LASTEXITCODE (expected $ExpectExit):`n$out"
    }
    return $out
}

# ── Phase 1: preflight ───────────────────────────────────────────────────────
Write-Phase 'Preflight'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
    Write-FailStep 'not elevated - run from an elevated interactive session'
} else {
    Write-Pass 'elevated'
}

$profiles = Get-NetFirewallProfile
$disabled = @($profiles | Where-Object { -not $_.Enabled })
if ($disabled.Count -gt 0) {
    Write-FailStep ("Windows Firewall is disabled on profile(s): " + (($disabled | ForEach-Object Name) -join ', ') +
        " - this harness will not flip a firewall the operator turned off. Run it on the elevated test VM.")
} else {
    Write-Pass 'all firewall profiles enabled'
}

# The consent loop is driven by Security 5152/5157 (Filtering Platform) audits.
# Reading audit policy itself needs elevation, so only attempt it when elevated.
if ($elevated) {
    try {
        $dropAudit = (auditpol /get /subcategory:'Filtering Platform Packet Drop' /r 2>&1 | Out-String)
        $script:AuditWasEnabled = $dropAudit -match 'Failure'
    } catch {
        $script:AuditWasEnabled = $false
    }

    if ($script:AuditWasEnabled) {
        Write-Pass 'Filtering Platform Packet Drop failure auditing already on'
    } else {
        Write-Host '  INFO  enabling Filtering Platform Packet Drop failure auditing for this run'
        auditpol /set /subcategory:'Filtering Platform Packet Drop' /failure:enable | Out-Null
    }
}

if ($script:Failures.Count -gt 0) {
    Write-Host "`nPREFLIGHT FAILED - this host cannot run the elevated E2E:" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 2
}

if ($PreflightOnly) {
    Write-Host "`nPREFLIGHT OK - this host can run the elevated E2E." -ForegroundColor Green
    exit 0
}

try {
    # ── Phase 2: service ─────────────────────────────────────────────────────
    Write-Phase 'Service'

    if ($InstallerPath) {
        if (-not (Test-Path $InstallerPath)) { throw "installer not found: $InstallerPath" }
        Write-Host "  INFO  installing $InstallerPath"
        Start-Process -FilePath $InstallerPath -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait
    }

    $svc = Get-Service -Name 'HostsGuardSvc' -ErrorAction SilentlyContinue
    if (-not $svc) { throw 'HostsGuardSvc is not installed - pass -InstallerPath' }
    if ($svc.Status -ne 'Running') { Start-Service HostsGuardSvc; Start-Sleep -Seconds 3 }
    Write-Pass 'HostsGuardSvc running'

    $script:Cli = Resolve-Cli
    $status = Invoke-Cli -CliArgs @('status')
    Write-Pass "CLI reached the service pipe ($(($status -split "`n")[0].Trim()))"

    # ── Phase 3: live COM rule write ─────────────────────────────────────────
    Write-Phase 'Live firewall rule write'

    $scratchExe = Join-Path $env:TEMP 'hg_e2e_target.exe'
    Copy-Item -Path (Join-Path $env:SystemRoot 'System32\curl.exe') -Destination $scratchExe -Force
    Invoke-Cli -CliArgs @('block-app', $scratchExe, 'out') | Out-Null
    $ruleName = 'HG_BlockApp_hg_e2e_target_Out'
    $liveRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($liveRule -and $liveRule.Enabled -eq 'True' -and $liveRule.Action -eq 'Block') {
        Write-Pass "live COM rule written and enabled: $ruleName"
    } else {
        Write-FailStep "expected live firewall rule $ruleName after block-app"
    }

    # Blocked in practice, not just on paper: the scratch exe must fail to dial out.
    $probe = & $scratchExe --silent --show-error --max-time 8 'http://neverssl.com/' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Pass "blocked executable cannot reach the network (curl exit $LASTEXITCODE)"
    } else {
        Write-FailStep 'the HG_-blocked executable still reached the network'
    }

    Invoke-Cli -CliArgs @('unblock-app', $scratchExe, 'out') | Out-Null
    if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Write-FailStep "rule $ruleName still present after unblock-app"
    } else {
        Write-Pass 'rule removed by unblock-app'
    }

    # ── Phase 4: consent loop (Security 5152/5157 -> broker -> ledger) ───────
    Write-Phase 'Consent path'

    $priorOutbound = ($profiles | Select-Object -First 1).DefaultOutboundAction
    Invoke-Cli -CliArgs @('mode', 'notify') | Out-Null
    $armed = Get-NetFirewallProfile | Where-Object { $_.DefaultOutboundAction -ne 'Block' }
    if (@($armed).Count -eq 0) {
        Write-Pass 'Notify mode armed default-outbound Block on every profile'
    } else {
        Write-FailStep ('Notify mode left profiles unblocked: ' + (($armed | ForEach-Object Name) -join ', '))
    }

    # Synthetic outbound dial that no allow rule covers -> audited drop.
    $stamp = (Get-Date).ToString('o')
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $null = $tcp.BeginConnect('203.0.113.1', 9, $null, $null)
        Start-Sleep -Seconds 3
        $tcp.Close()
    } catch { }

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $sawConsent = $false
    while (-not $sawConsent -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $events = Invoke-Cli -CliArgs @('events', '--limit', '100', '--since', $stamp)
        if ($events -match 'consent|5157|decision') { $sawConsent = $true }
    }

    if ($sawConsent) {
        Write-Pass 'service ledger recorded the consent path for the synthetic drop'
    } else {
        Write-FailStep "no consent-path ledger evidence within ${TimeoutSec}s (see 'HostsGuard.Cli events')"
    }

    # ── Phase 5: posture restore ─────────────────────────────────────────────
    Write-Phase 'Posture restore'

    Invoke-Cli -CliArgs @('mode', 'normal') | Out-Null
    Start-Sleep -Seconds 2
    $afterNormal = (Get-NetFirewallProfile | Select-Object -First 1).DefaultOutboundAction
    if ("$afterNormal" -eq "$priorOutbound") {
        Write-Pass "switching to Normal restored default-outbound ($afterNormal)"
    } else {
        Write-FailStep "Normal mode left default-outbound $afterNormal (prior $priorOutbound)"
    }

    # Restore-on-stop: arm again, stop the service, posture must come back.
    Invoke-Cli -CliArgs @('mode', 'notify') | Out-Null
    Stop-Service HostsGuardSvc -Force
    Start-Sleep -Seconds 3
    $afterStop = (Get-NetFirewallProfile | Select-Object -First 1).DefaultOutboundAction
    if ("$afterStop" -eq "$priorOutbound") {
        Write-Pass "service stop restored default-outbound ($afterStop)"
    } else {
        Write-FailStep "posture restore-on-stop failed: default-outbound is $afterStop (prior $priorOutbound)"
    }

    Start-Service HostsGuardSvc
    Start-Sleep -Seconds 3
    Invoke-Cli -CliArgs @('status') | Out-Null
    Write-Pass 'service restarted and reachable'
}
finally {
    if (-not $script:AuditWasEnabled) {
        auditpol /set /subcategory:'Filtering Platform Packet Drop' /failure:disable | Out-Null
    }

    if ($scratchExe -and (Test-Path $scratchExe)) {
        Remove-Item $scratchExe -Force -ErrorAction SilentlyContinue
    }
}

if ($script:Failures.Count -gt 0) {
    Write-Host "`nE2E FAILED ($($script:Failures.Count) assertion(s)):" -ForegroundColor Red
    $script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "`nE2E PASSED - live service, COM rule write, consent path, and posture restore all verified." -ForegroundColor Green
exit 0
