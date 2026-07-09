param(
    [switch]$RequireArtifacts
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$errors = [System.Collections.Generic.List[string]]::new()

function Add-Error([string]$Message) {
    $errors.Add($Message) | Out-Null
}

function Read-Text([string]$Path) {
    Get-Content -LiteralPath (Join-Path $repo $Path) -Raw
}

function Require-Contains([string]$Path, [string]$Needle, [string]$Label) {
    $text = Read-Text $Path
    if (-not $text.Contains($Needle)) {
        Add-Error "$Label missing '$Needle' in $Path"
    }
}

function Get-Sha256([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('X2') })
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

[xml]$props = Read-Text 'Directory.Build.props'
$version = $props.Project.PropertyGroup.Version | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($version)) {
    Add-Error 'Directory.Build.props does not define <Version>'
}

$iss = Read-Text 'installer-dotnet.iss'
if ($iss -notmatch "#define\s+MyAppVersion\s+`"$([regex]::Escape($version))`"") {
    Add-Error "installer-dotnet.iss MyAppVersion does not match $version"
}
if ($iss -notmatch "#define\s+MyAppVersionInfo\s+`"$([regex]::Escape($version))\.0`"") {
    Add-Error "installer-dotnet.iss MyAppVersionInfo does not match $version.0"
}

Require-Contains 'README.md' "version-$version-blue" 'README badge'
Require-Contains 'README.md' "HostsGuard-v$version-win-x64-dotnet-Setup.exe" 'README x64 artifact'
Require-Contains 'README.md' "HostsGuard-v$version-win-arm64-dotnet-Setup.exe" 'README arm64 artifact'
Require-Contains 'CHANGELOG.md' "## [$version] -" 'CHANGELOG heading'

foreach ($manifest in @(
    'winget/SysAdminDoc.HostsGuard.yaml',
    'winget/SysAdminDoc.HostsGuard.locale.en-US.yaml',
    'winget/SysAdminDoc.HostsGuard.installer.yaml'
)) {
    Require-Contains $manifest "PackageVersion: $version" "winget package version"
}

$installerManifest = Read-Text 'winget/SysAdminDoc.HostsGuard.installer.yaml'
foreach ($rid in @('win-x64', 'win-arm64')) {
    $fileName = "HostsGuard-v$version-$rid-dotnet-Setup.exe"
    $url = "https://github.com/SysAdminDoc/HostsGuard/releases/download/v$version/$fileName"
    if (-not $installerManifest.Contains("InstallerUrl: $url")) {
        Add-Error "winget installer URL missing $url"
    }

    $artifact = Join-Path $repo "installer_output\$fileName"
    if (Test-Path -LiteralPath $artifact) {
        $hash = Get-Sha256 $artifact
        if (-not $installerManifest.Contains("InstallerSha256: $hash")) {
            Add-Error "winget $rid SHA256 does not match $hash"
        }
    }
    elseif ($RequireArtifacts) {
        Add-Error "required artifact missing: $artifact"
    }
}

if ($errors.Count -ne 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Host "Release version gate: OK (v$version)"
