[CmdletBinding()]
param(
    [string]$AppPath = "",
    [string]$OutputDir = "",
    [string]$ReadmeImageDir = "",
    [int]$Width = 1600,
    [int]$Height = 1000,
    [int]$SettleMs = 1200,
    [string[]]$Tabs = @("Hosts Activity", "Alerts", "Hosts File", "Firewall Activity", "Firewall Rules", "Tools")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "artifacts\visual-smoke"
}

if ([string]::IsNullOrWhiteSpace($ReadmeImageDir)) {
    $ReadmeImageDir = Join-Path $repoRoot "docs\img"
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

function Get-ProjectVersion {
    [xml]$props = Get-Content -LiteralPath (Join-Path $repoRoot "Directory.Build.props") -Raw
    $version = $props.Project.PropertyGroup.Version | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "Directory.Build.props does not define <Version>."
    }

    return [string]$version
}

function Get-RelativeRepoPath([string]$Path) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $root = $repoRoot.TrimEnd('\') + '\'
    if ($resolved.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        return ($resolved.Substring($root.Length) -replace '\\', '/')
    }

    return $resolved
}

function Get-Sha256([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('X2') })
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Write-JsonFile([string]$Path, $Value) {
    $json = $Value | ConvertTo-Json -Depth 6
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, (($json -replace "`r`n", "`n") + "`n"), $utf8)
}

function Get-PngSize([string]$Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if (($bytes.Length -lt 24) -or
        ($bytes[0] -ne 0x89) -or
        ($bytes[1] -ne 0x50) -or
        ($bytes[2] -ne 0x4E) -or
        ($bytes[3] -ne 0x47)) {
        throw "Screenshot is not a PNG: $Path"
    }

    return [pscustomobject]@{
        width = (([int]$bytes[16] -shl 24) -bor ([int]$bytes[17] -shl 16) -bor ([int]$bytes[18] -shl 8) -bor [int]$bytes[19])
        height = (([int]$bytes[20] -shl 24) -bor ([int]$bytes[21] -shl 16) -bor ([int]$bytes[22] -shl 8) -bor [int]$bytes[23])
    }
}

function Get-BinaryVersion([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path -LiteralPath $Path).Path)
    return [ordered]@{
        path = Get-RelativeRepoPath $Path
        fileVersion = $info.FileVersion
        productVersion = $info.ProductVersion
    }
}

function Find-ServicePath([string]$ResolvedAppPath) {
    $appDir = Split-Path -Parent $ResolvedAppPath
    $appParent = Split-Path -Parent $appDir
    $candidates = @(
        (Join-Path $appParent "service\HostsGuard.Service.exe"),
        (Join-Path $repoRoot "src\HostsGuard.Service\bin\Debug\net10.0-windows\HostsGuard.Service.exe"),
        (Join-Path $repoRoot "src\HostsGuard.Service\bin\Release\net10.0-windows\HostsGuard.Service.exe"),
        (Join-Path $repoRoot "dist\dotnet\win-x64\service\HostsGuard.Service.exe"),
        (Join-Path $repoRoot "dist\dotnet\win-arm64\service\HostsGuard.Service.exe")
    )

    return $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

function Invoke-SmokeTheme {
    param(
        [ValidateSet("dark", "light")] [string]$Theme,
        [string]$Locale = "",
        [string]$RunName = ""
    )

    $directoryName = if ([string]::IsNullOrWhiteSpace($RunName)) { $Theme } else { $RunName }
    $themeDir = Join-Path $OutputDir $directoryName
    New-Item -ItemType Directory -Force -Path $themeDir | Out-Null
    Get-ChildItem -LiteralPath $themeDir -File -ErrorAction SilentlyContinue | Remove-Item -Force

    $args = @(
        "--uia-background",
        "--theme=$Theme",
        "--size=${Width}x${Height}",
        "--visual-smoke-settle-ms=$SettleMs",
        "--visual-smoke-output=$themeDir"
    )
    if (-not [string]::IsNullOrWhiteSpace($Locale)) {
        $args += "--locale=$Locale"
    }
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

$productVersion = Get-ProjectVersion
$resolvedAppPath = (Resolve-Path -LiteralPath $AppPath).Path
$servicePath = Find-ServicePath $resolvedAppPath

$summary = [ordered]@{
    productVersion = $productVersion
    generatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
    appPath = $resolvedAppPath
    outputDir = (Resolve-Path -LiteralPath $OutputDir).Path
    expectedSize = "${Width}x${Height}"
    readmeImageDir = $ReadmeImageDir
    runs = @()
}

foreach ($theme in @("dark", "light")) {
    $summary.runs += Invoke-SmokeTheme -Theme $theme
}
$summary.runs += Invoke-SmokeTheme -Theme "dark" -Locale "qps-ploc" -RunName "pseudo"

$summaryPath = Join-Path $OutputDir "visual-smoke-summary.json"
Write-JsonFile $summaryPath $summary

$failures = @($summary.runs | ForEach-Object { $_.failures } | Where-Object { $_ })
if ($failures.Count -gt 0) {
    $message = "Visual smoke failed:`n - " + ($failures -join "`n - ") + "`nEvidence: $summaryPath"
    throw $message
}

New-Item -ItemType Directory -Force -Path $ReadmeImageDir | Out-Null
$readmeScreenshots = @()
foreach ($theme in @("dark", "light")) {
    $run = $summary.runs | Where-Object { $_.theme -eq $theme -and $_.locale -ne "qps-ploc" } | Select-Object -First 1
    $capture = @($run.captures | Where-Object { $_.tab -eq "Hosts Activity" }) | Select-Object -First 1
    if ($null -eq $capture) {
        throw "Visual smoke did not capture the Hosts Activity README screenshot for $theme theme."
    }

    $targetPath = Join-Path $ReadmeImageDir "hosts-activity-$theme.png"
    Copy-Item -LiteralPath $capture.path -Destination $targetPath -Force
    $size = Get-PngSize $targetPath
    $file = Get-Item -LiteralPath $targetPath
    $readmeScreenshots += [ordered]@{
        theme = $theme
        tab = "Hosts Activity"
        path = Get-RelativeRepoPath $targetPath
        sha256 = Get-Sha256 $targetPath
        bytes = $file.Length
        width = $size.width
        height = $size.height
        averageLuminance = $capture.averageLuminance
        luminanceRange = $capture.luminanceRange
        opaqueRatio = $capture.opaqueRatio
        bottomOpaqueRatio = $capture.bottomOpaqueRatio
        contentTileRatio = $capture.contentTileRatio
    }
}

$manifest = [ordered]@{
    schemaVersion = 2
    product = "HostsGuard"
    version = $productVersion
    generatedAtUtc = [DateTimeOffset]::UtcNow.ToString("O")
    expectedSize = "${Width}x${Height}"
    app = Get-BinaryVersion $resolvedAppPath
    service = if ($null -ne $servicePath) { Get-BinaryVersion $servicePath } else { $null }
    sourceSummary = Get-RelativeRepoPath $summaryPath
    readmeScreenshots = $readmeScreenshots
}

$manifestPath = Join-Path $ReadmeImageDir "visual-smoke-manifest.json"
Write-JsonFile $manifestPath $manifest

"Visual smoke passed. Evidence: $summaryPath"
"README screenshots refreshed. Manifest: $manifestPath"
