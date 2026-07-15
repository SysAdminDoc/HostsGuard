using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

namespace HostsGuard.Windows;

public sealed record HyperVFirewallProfile(
    string Name,
    bool Enabled,
    string DefaultInboundAction,
    string DefaultOutboundAction,
    bool AllowLocalFirewallRules);

public sealed record HyperVFirewallWorkload(
    string CreatorId,
    string DisplayName,
    bool SettingPresent,
    bool Enabled,
    string DefaultInboundAction,
    string DefaultOutboundAction,
    bool AllowHostPolicyMerge,
    bool LoopbackEnabled,
    IReadOnlyList<HyperVFirewallProfile> Profiles);

public sealed record HyperVFirewallSnapshot(
    bool Available,
    string ErrorCode,
    DateTime CheckedAtUtc,
    IReadOnlyList<HyperVFirewallWorkload> Workloads);

public interface IHyperVFirewallInventory
{
    Task<HyperVFirewallSnapshot> SnapshotAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Reads the effective Hyper-V firewall VM settings and per-network-profile
/// defaults from the Windows NetSecurity cmdlets. The query is read-only and
/// intentionally stops at the Windows VM-creator boundary: it cannot identify
/// processes inside WSL or another guest.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PowerShellHyperVFirewallInventory : IHyperVFirewallInventory
{
    private const string JsonPrefix = "HG_HYPERV_JSON:";
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(10);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly Func<CancellationToken, Task<HyperVCommandResult>> _runner;
    private readonly Func<DateTime> _utcNow;

    public PowerShellHyperVFirewallInventory()
        : this(RunPowerShellAsync, () => DateTime.UtcNow)
    {
    }

    internal PowerShellHyperVFirewallInventory(
        Func<CancellationToken, Task<HyperVCommandResult>> runner,
        Func<DateTime>? utcNow = null)
    {
        _runner = runner ?? throw new ArgumentNullException(nameof(runner));
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
    }

    public async Task<HyperVFirewallSnapshot> SnapshotAsync(CancellationToken cancellationToken = default)
    {
        var checkedAt = DateTime.SpecifyKind(_utcNow(), DateTimeKind.Utc);
        HyperVCommandResult result;
        try
        {
            result = await _runner(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            return Unavailable(checkedAt, "powershell_unavailable");
        }

        if (result.TimedOut)
        {
            return Unavailable(checkedAt, "powershell_query_timeout");
        }

        if (result.ExitCode != 0)
        {
            return Unavailable(checkedAt, "powershell_query_failed");
        }

        return ParseOutput(result.StandardOutput, checkedAt);
    }

    internal static HyperVFirewallSnapshot ParseOutput(string output, DateTime checkedAtUtc)
    {
        var checkedAt = DateTime.SpecifyKind(checkedAtUtc, DateTimeKind.Utc);
        var json = output.ReplaceLineEndings("\n")
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .LastOrDefault(line => line.StartsWith(JsonPrefix, StringComparison.Ordinal));
        if (json is null)
        {
            return Unavailable(checkedAt, "invalid_query_output");
        }

        try
        {
            var payload = JsonSerializer.Deserialize<HyperVPayload>(json[JsonPrefix.Length..], JsonOptions);
            if (payload is null)
            {
                return Unavailable(checkedAt, "invalid_query_output");
            }

            if (!payload.Available)
            {
                return Unavailable(checkedAt, HyperVFirewallText.Clean(
                    payload.ErrorCode, 64, "cmdlet_unavailable"));
            }

            var workloads = (payload.Workloads ?? [])
                .Select(ToWorkload)
                .Where(workload => workload.CreatorId.Length != 0)
                .GroupBy(workload => workload.CreatorId, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .OrderBy(workload => workload.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(workload => workload.CreatorId, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return new HyperVFirewallSnapshot(true, string.Empty, checkedAt, workloads);
        }
        catch (JsonException)
        {
            return Unavailable(checkedAt, "invalid_query_output");
        }
    }

    private static HyperVFirewallWorkload ToWorkload(HyperVWorkloadPayload payload)
    {
        var profiles = (payload.Profiles ?? [])
            .Select(profile => new HyperVFirewallProfile(
                HyperVFirewallText.Clean(profile.Name, 32, "Unknown"),
                profile.Enabled,
                HyperVFirewallText.Clean(profile.DefaultInboundAction, 32, "Unknown"),
                HyperVFirewallText.Clean(profile.DefaultOutboundAction, 32, "Unknown"),
                profile.AllowLocalFirewallRules))
            .OrderBy(profile => ProfileOrder(profile.Name))
            .ThenBy(profile => profile.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new HyperVFirewallWorkload(
            HyperVFirewallText.Clean(payload.CreatorId, 128, string.Empty),
            HyperVFirewallText.Clean(payload.DisplayName, 128, string.Empty),
            payload.SettingPresent,
            payload.Enabled,
            HyperVFirewallText.Clean(payload.DefaultInboundAction, 32, "Unknown"),
            HyperVFirewallText.Clean(payload.DefaultOutboundAction, 32, "Unknown"),
            payload.AllowHostPolicyMerge,
            payload.LoopbackEnabled,
            profiles);
    }

    private static int ProfileOrder(string profile) => profile.ToLowerInvariant() switch
    {
        "domain" => 0,
        "private" => 1,
        "public" => 2,
        _ => 3,
    };

    private static HyperVFirewallSnapshot Unavailable(DateTime checkedAt, string errorCode) => new(
        false,
        HyperVFirewallText.Clean(errorCode, 64, "query_unavailable"),
        checkedAt,
        []);

    private static async Task<HyperVCommandResult> RunPowerShellAsync(CancellationToken cancellationToken)
    {
        var executable = Path.Combine(
            Environment.SystemDirectory,
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(PowerShellScript));
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            },
        };
        process.StartInfo.ArgumentList.Add("-NoLogo");
        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-EncodedCommand");
        process.StartInfo.ArgumentList.Add(encoded);

        if (!process.Start())
        {
            throw new InvalidOperationException("Unable to start the Hyper-V firewall inventory query.");
        }

        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = new CancellationTokenSource(QueryTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
            await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
            return new HyperVCommandResult(process.ExitCode, stdout.Result, stderr.Result, false);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                // The process exited between cancellation and termination.
            }

            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            return new HyperVCommandResult(-1, string.Empty, string.Empty, true);
        }
    }

    private const string PowerShellScript = """
        $ErrorActionPreference = 'Stop'
        function Get-Text($item, [string[]]$names) {
            if ($null -eq $item) { return '' }
            foreach ($name in $names) {
                $property = $item.PSObject.Properties[$name]
                if ($null -ne $property -and $null -ne $property.Value) {
                    $value = ([string]$property.Value) -replace '[\p{Cc}\p{Cf}]', ' '
                    $value = $value.Trim()
                    if ($value.Length -gt 0) { return $value }
                }
            }
            return ''
        }
        function Get-Bool($item, [string]$name) {
            if ($null -eq $item) { return $false }
            $property = $item.PSObject.Properties[$name]
            if ($null -eq $property -or $null -eq $property.Value) { return $false }
            return [bool]$property.Value
        }
        if ($null -eq (Get-Command Get-NetFirewallHyperVProfile -ErrorAction SilentlyContinue) -or
            $null -eq (Get-Command Get-NetFirewallHyperVVMSetting -ErrorAction SilentlyContinue)) {
            $payload = [ordered]@{ available = $false; errorCode = 'cmdlet_unavailable'; workloads = @() }
            Write-Output ('HG_HYPERV_JSON:' + ($payload | ConvertTo-Json -Depth 8 -Compress))
            exit 0
        }
        $settings = @(Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -ErrorAction Stop)
        $profiles = @(Get-NetFirewallHyperVProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $ids = @(
            foreach ($item in @($settings) + @($profiles)) {
                $id = Get-Text $item @('VMCreatorId', 'Name')
                if ($id.Length -gt 0) { $id }
            }
        ) | Sort-Object -Unique
        $workloads = @(
            foreach ($creatorId in $ids) {
                $setting = @($settings | Where-Object { (Get-Text $_ @('VMCreatorId', 'Name')) -eq $creatorId }) | Select-Object -First 1
                $creatorProfiles = @($profiles | Where-Object { (Get-Text $_ @('VMCreatorId', 'Name')) -eq $creatorId })
                $displayName = Get-Text $setting @('ElementName', 'Description')
                if ($displayName.Length -eq 0 -and $creatorProfiles.Count -gt 0) {
                    $displayName = Get-Text $creatorProfiles[0] @('ElementName', 'Description')
                }
                $profileRows = @(
                    foreach ($profile in $creatorProfiles) {
                        [ordered]@{
                            name = Get-Text $profile @('Profile')
                            enabled = Get-Bool $profile 'Enabled'
                            defaultInboundAction = Get-Text $profile @('DefaultInboundAction')
                            defaultOutboundAction = Get-Text $profile @('DefaultOutboundAction')
                            allowLocalFirewallRules = Get-Bool $profile 'AllowLocalFirewallRules'
                        }
                    }
                )
                [ordered]@{
                    creatorId = $creatorId
                    displayName = $displayName
                    settingPresent = ($null -ne $setting)
                    enabled = Get-Bool $setting 'Enabled'
                    defaultInboundAction = Get-Text $setting @('DefaultInboundAction')
                    defaultOutboundAction = Get-Text $setting @('DefaultOutboundAction')
                    allowHostPolicyMerge = Get-Bool $setting 'AllowHostPolicyMerge'
                    loopbackEnabled = Get-Bool $setting 'LoopbackEnabled'
                    profiles = $profileRows
                }
            }
        )
        $payload = [ordered]@{ available = $true; errorCode = ''; workloads = $workloads }
        Write-Output ('HG_HYPERV_JSON:' + ($payload | ConvertTo-Json -Depth 8 -Compress))
        """;

    private sealed class HyperVPayload
    {
        public bool Available { get; init; }
        public string ErrorCode { get; init; } = string.Empty;
        public List<HyperVWorkloadPayload>? Workloads { get; init; }
    }

    private sealed class HyperVWorkloadPayload
    {
        public string CreatorId { get; init; } = string.Empty;
        public string DisplayName { get; init; } = string.Empty;
        public bool SettingPresent { get; init; }
        public bool Enabled { get; init; }
        public string DefaultInboundAction { get; init; } = string.Empty;
        public string DefaultOutboundAction { get; init; } = string.Empty;
        public bool AllowHostPolicyMerge { get; init; }
        public bool LoopbackEnabled { get; init; }
        public List<HyperVProfilePayload>? Profiles { get; init; }
    }

    private sealed class HyperVProfilePayload
    {
        public string Name { get; init; } = string.Empty;
        public bool Enabled { get; init; }
        public string DefaultInboundAction { get; init; } = string.Empty;
        public string DefaultOutboundAction { get; init; } = string.Empty;
        public bool AllowLocalFirewallRules { get; init; }
    }
}

internal readonly record struct HyperVCommandResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut);

internal static class HyperVFirewallText
{
    internal static string Clean(string? value, int maxLength, string fallback)
    {
        var cleaned = new string((value ?? string.Empty)
            .Where(character => !char.IsControl(character) &&
                                CharUnicodeInfo.GetUnicodeCategory(character) != UnicodeCategory.Format)
            .ToArray())
            .Trim();
        if (cleaned.Length == 0)
        {
            return fallback;
        }

        return cleaned.Length <= maxLength ? cleaned : cleaned[..maxLength];
    }
}
