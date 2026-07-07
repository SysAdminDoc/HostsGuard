[CmdletBinding()]
param(
    [string]$AppPath = "",
    [string]$OutputDir = "",
    [int]$Width = 1600,
    [int]$Height = 1000,
    [int]$SettleMs = 1200,
    [string[]]$Tabs = @("Hosts Activity", "Hosts File", "Firewall Activity", "Firewall Rules", "Tools")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "artifacts\visual-smoke"
}

if ([string]::IsNullOrWhiteSpace($AppPath)) {
    $candidates = @(
        (Join-Path $repoRoot "dist\dotnet\win-x64\app\HostsGuard.App.exe"),
        (Join-Path $repoRoot "dist\dotnet\app\HostsGuard.App.exe"),
        (Join-Path $repoRoot "src\HostsGuard.App\bin\Debug\net10.0-windows\HostsGuard.App.exe"),
        (Join-Path $repoRoot "src\HostsGuard.App\bin\Release\net10.0-windows\win-x64\HostsGuard.App.exe"),
        "C:\Program Files\HostsGuard\app\HostsGuard.App.exe",
        "C:\Program Files\HostsGuard\HostsGuard.App.exe"
    )
    $AppPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

if (-not (Test-Path -LiteralPath $AppPath)) {
    throw "HostsGuard.App.exe not found. Build the app or pass -AppPath."
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Invoke-SmokeTheme {
    param([ValidateSet("dark", "light")] [string]$Theme)

    $themeDir = Join-Path $OutputDir $Theme
    New-Item -ItemType Directory -Force -Path $themeDir | Out-Null
    Get-ChildItem -LiteralPath $themeDir -File -ErrorAction SilentlyContinue | Remove-Item -Force

    $args = @(
        "--uia-background",
        "--theme=$Theme",
        "--size=${Width}x${Height}",
        "--visual-smoke-settle-ms=$SettleMs",
        "--visual-smoke-output=$themeDir"
    )
    $process = Start-Process -FilePath $AppPath -ArgumentList $args -PassThru
    if (-not $process.WaitForExit(90000)) {
        Stop-Process -Id $process.Id -Force
        throw "HostsGuard visual smoke timed out for $Theme theme."
    }

    $runPath = Join-Path $themeDir "visual-smoke-run.json"
    if (-not (Test-Path -LiteralPath $runPath)) {
        throw "HostsGuard did not write visual smoke evidence for $Theme theme. Exit code: $($process.ExitCode)."
    }

    $run = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json
    $captureCount = @($run.captures).Count
    if ($captureCount -ne $Tabs.Count) {
        $run.failures += "Captured $captureCount tabs for $Theme theme; expected $($Tabs.Count)."
    }

    if ($process.ExitCode -ne 0 -and @($run.failures).Count -eq 0) {
        $run.failures += "HostsGuard exited with code $($process.ExitCode) for $Theme theme."
    }

    return $run
}

$summary = [ordered]@{
    appPath = (Resolve-Path -LiteralPath $AppPath).Path
    outputDir = (Resolve-Path -LiteralPath $OutputDir).Path
    expectedSize = "${Width}x${Height}"
    runs = @()
}

foreach ($theme in @("dark", "light")) {
    $summary.runs += Invoke-SmokeTheme -Theme $theme
}

$summaryPath = Join-Path $OutputDir "visual-smoke-summary.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding utf8

$failures = @($summary.runs | ForEach-Object { $_.failures } | Where-Object { $_ })
if ($failures.Count -gt 0) {
    $message = "Visual smoke failed:`n - " + ($failures -join "`n - ") + "`nEvidence: $summaryPath"
    throw $message
}

"Visual smoke passed. Evidence: $summaryPath"
