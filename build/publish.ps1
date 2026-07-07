# HostsGuard .NET publish pipeline (NET-050 / NET-142).
# Single-file, self-contained Windows builds of the service, the WPF app, and
# the CLI into dist\dotnet\<rid>\. Trimming is deliberately OFF (WPF, gRPC
# codegen, and COM interop depend on reflection the trimmer cannot prove) and so
# is ReadyToRun (crossgen2 rejects TraceEvent's duplicate Dia2Lib assets; the
# start-time gain is irrelevant for a long-running service). Run from anywhere;
# paths resolve relative to this script.
param(
    [string]$Configuration = 'Release',
    [string[]]$RuntimeIdentifier = @('win-x64'),
    [switch]$AllRuntimes,
    [switch]$SkipSmoke
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$outRoot = Join-Path $root 'dist\dotnet'
$supportedRuntimeIds = @('win-x64', 'win-arm64')
$runtimeIds = if ($AllRuntimes) { $supportedRuntimeIds } else { $RuntimeIdentifier }
$runtimeIds = @($runtimeIds | Select-Object -Unique)
foreach ($rid in $runtimeIds) {
    if ($supportedRuntimeIds -notcontains $rid) {
        throw "Unsupported runtime identifier '$rid'. Supported: $($supportedRuntimeIds -join ', ')"
    }
}

# Clean before build. Stale artifacts never ship next to fresh ones.
if (Test-Path $outRoot) {
    Remove-Item $outRoot -Recurse -Force
}

$projects = @(
    @{ Name = 'HostsGuard.Service'; Dir = 'service' },
    @{ Name = 'HostsGuard.App';     Dir = 'app' },
    @{ Name = 'HostsGuard.Cli';     Dir = 'cli' }
)

function Test-CanRunRuntime([string]$Rid) {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    if ($Rid -eq 'win-arm64') {
        return $arch -eq 'Arm64'
    }

    return $arch -in @('X64', 'Arm64')
}

foreach ($rid in $runtimeIds) {
    $out = Join-Path $outRoot $rid
    foreach ($project in $projects) {
        $name = $project.Name
        Write-Host "publishing $name ($rid) ..." -ForegroundColor Cyan
        dotnet publish (Join-Path $root "src\$name\$name.csproj") `
            -c $Configuration -r $rid --self-contained true `
            -p:PublishSingleFile=true `
            -p:IncludeNativeLibrariesForSelfExtract=true `
            -p:EnableCompressionInSingleFile=true `
            -o (Join-Path $out $project.Dir) `
            --nologo -v minimal
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed for $name ($rid, exit $LASTEXITCODE)"
        }
    }

    if (-not $SkipSmoke -and (Test-CanRunRuntime $rid)) {
        Write-Host "`nrelease-smoke ($rid):" -ForegroundColor Cyan
        & (Join-Path $out 'cli\HostsGuard.Cli.exe') release-smoke
        if ($LASTEXITCODE -ne 0) {
            throw "release-smoke failed for $rid (exit $LASTEXITCODE)"
        }
    }
    elseif (-not $SkipSmoke) {
        Write-Host "`nrelease-smoke ($rid): skipped on $([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture)" -ForegroundColor Yellow
    }
}

Get-ChildItem $outRoot -Recurse -Include *.exe | Sort-Object FullName | ForEach-Object {
    '{0,10:n1} MB  {1}' -f ($_.Length / 1MB), $_.FullName.Substring($outRoot.Length + 1)
}
