# HostsGuard .NET publish pipeline (NET-050).
# Single-file, self-contained win-x64 builds of the service, the WPF app, and
# the CLI into dist\dotnet\. Trimming is deliberately OFF (WPF, gRPC codegen,
# and COM interop depend on reflection the trimmer cannot prove) and so is
# ReadyToRun (crossgen2 rejects TraceEvent's duplicate Dia2Lib assets; the
# start-time gain is irrelevant for a long-running service). Run from
# anywhere; paths resolve relative to this script.
param(
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $root 'dist\dotnet'

# Clean before build — stale artifacts never ship next to fresh ones.
if (Test-Path $out) {
    Remove-Item $out -Recurse -Force
}

$projects = @(
    @{ Name = 'HostsGuard.Service'; Dir = 'service' },
    @{ Name = 'HostsGuard.App';     Dir = 'app' },
    @{ Name = 'HostsGuard.Cli';     Dir = 'cli' }
)

foreach ($project in $projects) {
    $name = $project.Name
    Write-Host "publishing $name ..." -ForegroundColor Cyan
    dotnet publish (Join-Path $root "src\$name\$name.csproj") `
        -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true `
        -o (Join-Path $out $project.Dir) `
        --nologo -v minimal
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for $name (exit $LASTEXITCODE)"
    }
}

Write-Host "`nrelease-smoke:" -ForegroundColor Cyan
& (Join-Path $out 'cli\HostsGuard.Cli.exe') release-smoke
if ($LASTEXITCODE -ne 0) {
    throw "release-smoke failed (exit $LASTEXITCODE)"
}

Get-ChildItem $out -Recurse -Include *.exe | ForEach-Object {
    '{0,10:n1} MB  {1}' -f ($_.Length / 1MB), $_.FullName.Substring($out.Length + 1)
}
