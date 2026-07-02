using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.App.ViewModels;

/// <summary>Editable row in the scheduled-blocking editor.</summary>
public sealed partial class ScheduleRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _target = string.Empty;

    [ObservableProperty]
    private string _daysText = string.Empty; // "Mon,Tue" or "0,1"

    [ObservableProperty]
    private string _start = "22:00";

    [ObservableProperty]
    private string _end = "06:00";

    /// <summary>Parse day names or indices into the proto 0=Mon..6=Sun form.</summary>
    public IReadOnlyList<int> ParseDays()
    {
        var days = new List<int>();
        foreach (var token in DaysText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(token, out var idx))
            {
                days.Add(idx);
                continue;
            }

            var named = Scheduling.Weekdays.ToList()
                .FindIndex(w => w.Equals(token, StringComparison.OrdinalIgnoreCase) ||
                                token.StartsWith(w, StringComparison.OrdinalIgnoreCase));
            if (named >= 0)
            {
                days.Add(named);
            }
        }

        return days.Distinct().ToList();
    }

    public static ScheduleRowViewModel From(Schedule s) => new()
    {
        Target = s.Target,
        DaysText = string.Join(",", s.Days.Select(d => d is >= 0 and <= 6 ? Scheduling.Weekdays[d] : d.ToString(System.Globalization.CultureInfo.InvariantCulture))),
        Start = s.Start,
        End = s.End,
    };
}

/// <summary>Row VM for a hosts-file backup available to restore.</summary>
public sealed partial class BackupRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _fileName = string.Empty;

    [ObservableProperty]
    private string _created = string.Empty;

    [ObservableProperty]
    private long _sizeBytes;

    public string Label => $"{FileName} — {Created} ({SizeBytes / 1024.0:0.#} KB)";
}

/// <summary>Row VM for a one-click blockable service.</summary>
public sealed partial class BlockableServiceViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private bool _blocked;

    [ObservableProperty]
    private int _domainCount;

    [ObservableProperty]
    private string _note = string.Empty;

    public string Label => $"{Name} ({DomainCount})";
}

/// <summary>
/// Tools tab: DNS flush + resolver switching, one-click blocked services +
/// Windows telemetry preset, scheduled-blocking editor, hosts backup, ACL
/// hardening, redacted support-bundle export, and a domain inspector. Every
/// action round-trips the service and surfaces the typed ack.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class ToolsViewModel : ObservableObject
{
    public static readonly IReadOnlyList<(string Name, string[] Servers)> ResolverPresets = new[]
    {
        ("DHCP (default)", Array.Empty<string>()),
        ("Cloudflare (1.1.1.1)", new[] { "1.1.1.1", "1.0.0.1" }),
        ("Google (8.8.8.8)", new[] { "8.8.8.8", "8.8.4.4" }),
        ("Quad9 (9.9.9.9)", new[] { "9.9.9.9", "149.112.112.112" }),
    };

    private readonly HostsServiceClient _client;
    private readonly IConfirm _confirm;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private string _selectedResolver = "DHCP (default)";

    [ObservableProperty]
    private string _inspectDomain = string.Empty;

    [ObservableProperty]
    private string _inspectResult = string.Empty;

    // Settings lock (NET-079).
    [ObservableProperty]
    private bool _lockEnabled;

    [ObservableProperty]
    private string _lockPassword = string.Empty;

    [ObservableProperty]
    private int _unlockMinutes = 15;

    [ObservableProperty]
    private string _lockStatus = string.Empty;

    public ToolsViewModel(HostsServiceClient client, IConfirm confirm)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _confirm = confirm ?? throw new ArgumentNullException(nameof(confirm));
    }

    public ObservableCollection<ScheduleRowViewModel> Schedules { get; } = new();

    public ObservableCollection<BlockableServiceViewModel> Services { get; } = new();

    public static IReadOnlyList<string> ResolverNames { get; } = ResolverPresets.Select(p => p.Name).ToList();

    [RelayCommand]
    public async Task FlushDnsAsync()
    {
        var ack = await _client.Dns.FlushCacheAsync(new Empty());
        StatusText = ack.Message;
    }

    // ─── Settings lock (NET-079) ─────────────────────────────────────────────

    [RelayCommand]
    public async Task LoadLockStateAsync()
    {
        var state = await _client.Policy.GetLockStateAsync(new Empty());
        LockEnabled = state.Enabled;
        LockStatus = state.Enabled
            ? state.Unlocked ? "Locked (temporarily unlocked)" : "Locked"
            : "Not locked";
    }

    [RelayCommand]
    public async Task EnableLockAsync()
    {
        var ack = await _client.Policy.SetLockAsync(new LockRequest { Action = "enable", Password = LockPassword });
        LockStatus = ack.Message;
        LockPassword = string.Empty;
        await LoadLockStateAsync();
    }

    [RelayCommand]
    public async Task DisableLockAsync()
    {
        var ack = await _client.Policy.SetLockAsync(new LockRequest { Action = "disable", Password = LockPassword });
        LockStatus = ack.Message;
        LockPassword = string.Empty;
        await LoadLockStateAsync();
    }

    [RelayCommand]
    public async Task UnlockAsync()
    {
        var ack = await _client.Policy.UnlockAsync(new LockRequest { Password = LockPassword, Minutes = UnlockMinutes });
        LockStatus = ack.Message;
        LockPassword = string.Empty;
        await LoadLockStateAsync();
    }

    [RelayCommand]
    public async Task ProtectHostsAsync()
    {
        var ack = await _client.Policy.SetHostsProtectionAsync(new HostsProtectionRequest { Enabled = true });
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task ApplyResolverAsync()
    {
        var preset = ResolverPresets.FirstOrDefault(p => p.Name == SelectedResolver);
        var request = new ResolverRequest();
        request.Servers.AddRange(preset.Servers ?? Array.Empty<string>());
        var ack = await _client.Dns.SetResolverAsync(request);
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task BackupHostsAsync()
    {
        var ack = await _client.Hosts.BackupHostsAsync(new Empty());
        StatusText = ack.Ok ? $"Backup written: {ack.Message}" : ack.Message;
        await LoadBackupsAsync();
    }

    // ─── Backup restore ───────────────────────────────────────────────────────

    [ObservableProperty]
    private BackupRowViewModel? _selectedBackup;

    public ObservableCollection<BackupRowViewModel> Backups { get; } = new();

    [RelayCommand]
    public async Task LoadBackupsAsync()
    {
        var list = await _client.Hosts.ListBackupsAsync(new Empty());
        Backups.Clear();
        foreach (var entry in list.Entries)
        {
            Backups.Add(new BackupRowViewModel
            {
                FileName = entry.FileName,
                Created = entry.Created,
                SizeBytes = entry.SizeBytes,
            });
        }

        SelectedBackup = Backups.FirstOrDefault();
    }

    [RelayCommand]
    public async Task RestoreBackupAsync()
    {
        if (SelectedBackup is null)
        {
            StatusText = "No backup selected";
            return;
        }

        if (!_confirm.Confirm("Restore hosts backup",
            $"Replace the live hosts file with '{SelectedBackup.FileName}'? The current file is backed up first."))
        {
            return;
        }

        var ack = await _client.Hosts.RestoreBackupAsync(new BackupRequest { FileName = SelectedBackup.FileName });
        StatusText = ack.Message;
        if (ack.Ok)
        {
            await LoadBackupsAsync();
        }
    }

    [RelayCommand]
    public async Task HardenAclAsync()
    {
        var ack = await _client.Hosts.HardenAclAsync(new Empty());
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task ExportBundleAsync()
    {
        var ack = await _client.Diagnostics.ExportSupportBundleAsync(new Empty());
        StatusText = ack.Ok ? $"Support bundle: {ack.Message}" : ack.Message;
    }

    [RelayCommand]
    public async Task InspectAsync()
    {
        var result = await _client.Dns.InspectAsync(new DomainRequest { Domain = InspectDomain });
        var records = result.Records.Count == 0
            ? "no records"
            : string.Join("; ", result.Records.Select(r => $"{r.Type} {r.Value}"));
        InspectResult = $"{(result.Blocked ? "BLOCKED" : "reachable")} — {records} ({result.LatencyMs} ms)";
    }

    [ObservableProperty]
    private string _defenderStatusText = string.Empty;

    [RelayCommand]
    public async Task LoadDefenderStatusAsync()
    {
        var status = await _client.Diagnostics.GetDefenderStatusAsync(new Empty());
        DefenderStatusText = !status.Available
            ? "Defender: not accessible"
            : status.HostsExcluded
                ? "Defender: hosts file is excluded"
                : status.PossibleRevert
                    ? "Defender: hosts file NOT excluded — blocks are missing (possible Defender revert)"
                    : "Defender: hosts file not excluded (HostsFileHijack detection may remove telemetry blocks)";
    }

    [RelayCommand]
    public async Task AddDefenderExclusionAsync()
    {
        var ack = await _client.Hosts.AddDefenderExclusionAsync(new Empty());
        StatusText = ack.Message;
        await LoadDefenderStatusAsync();
    }

    [RelayCommand]
    public async Task RefreshThreatIntelAsync()
    {
        StatusText = "Refreshing threat intel…";
        var ack = await _client.Lists.RefreshThreatIntelAsync(new Empty());
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task RefreshGeoIpAsync()
    {
        StatusText = "Downloading GeoIP database…";
        var ack = await _client.Lists.RefreshGeoIpAsync(new Empty());
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task EmergencyResetAsync()
    {
        if (!_confirm.Confirm("Emergency reset",
            "Reset the hosts file to Windows defaults? All HostsGuard blocks are removed from the file."))
        {
            return;
        }

        var ack = await _client.Hosts.EmergencyResetAsync(new Empty());
        StatusText = ack.Message;
    }

    // ─── Network profiles ─────────────────────────────────────────────────────

    [ObservableProperty]
    private string _activeProfile = string.Empty;

    [ObservableProperty]
    private string? _selectedProfile;

    [ObservableProperty]
    private string _newProfileName = string.Empty;

    public ObservableCollection<string> Profiles { get; } = new();

    [RelayCommand]
    public async Task LoadProfilesAsync()
    {
        var list = await _client.Policy.ListProfilesAsync(new Empty());
        Profiles.Clear();
        foreach (var name in list.Names)
        {
            Profiles.Add(name);
        }

        ActiveProfile = list.Active.Length != 0 ? $"Active: {list.Active}" : "No active profile";
        SelectedProfile = list.Names.Contains(list.Active) ? list.Active : Profiles.FirstOrDefault();
    }

    [RelayCommand]
    public async Task SaveProfileAsync()
    {
        var ack = await _client.Policy.SaveProfileAsync(new ProfileRequest { Name = NewProfileName });
        StatusText = ack.Message;
        if (ack.Ok)
        {
            NewProfileName = string.Empty;
            await LoadProfilesAsync();
        }
    }

    [RelayCommand]
    public async Task SwitchProfileAsync()
    {
        if (string.IsNullOrEmpty(SelectedProfile))
        {
            return;
        }

        var ack = await _client.Policy.SwitchProfileAsync(new ProfileRequest { Name = SelectedProfile });
        StatusText = ack.Message;
        await LoadProfilesAsync();
    }

    [RelayCommand]
    public async Task DeleteProfileAsync()
    {
        if (string.IsNullOrEmpty(SelectedProfile) ||
            !_confirm.Confirm("Delete profile", $"Delete profile '{SelectedProfile}'?"))
        {
            return;
        }

        var ack = await _client.Policy.DeleteProfileAsync(new ProfileRequest { Name = SelectedProfile });
        StatusText = ack.Message;
        await LoadProfilesAsync();
    }

    // ─── Encrypted DNS (DoH/DoT) ──────────────────────────────────────────────

    [ObservableProperty]
    private string _dohStatusText = string.Empty;

    [ObservableProperty]
    private bool _dohBlockingActive;

    [ObservableProperty]
    private bool _quicBlockingActive;

    [ObservableProperty]
    private bool _cnameCloakActive;

    [ObservableProperty]
    private string _dohUrl = string.Empty;

    [ObservableProperty]
    private string _dohSha256 = string.Empty;

    [RelayCommand]
    public async Task LoadDohStatusAsync()
    {
        var status = await _client.Dns.GetDohStatusAsync(new Empty());
        DohBlockingActive = status.BlockingActive;
        QuicBlockingActive = status.QuicBlocked;
        CnameCloakActive = status.CnameCloak;
        DohStatusText = status.Updated.Length != 0
            ? $"DoH intelligence: {status.ResolverIps} resolver IPs; {status.Source}; updated {status.Updated}"
            : $"DoH intelligence: {status.ResolverIps} built-in resolver IPs; no refresh yet";
    }

    [RelayCommand]
    public async Task ToggleQuicAsync()
    {
        var ack = QuicBlockingActive
            ? await _client.Firewall.UnblockQuicAsync(new Empty())
            : await _client.Firewall.BlockQuicAsync(new Empty());
        StatusText = ack.Message;
        await LoadDohStatusAsync();
    }

    [RelayCommand]
    public async Task ToggleCnameCloakAsync()
    {
        var ack = await _client.Dns.SetCnameCloakAsync(new CnameCloakRequest { Enabled = !CnameCloakActive });
        StatusText = ack.Message;
        await LoadDohStatusAsync();
    }

    [RelayCommand]
    public async Task ApplyBaselineAsync()
    {
        var ack = await _client.Consent.ApplyBaselineAsync(new Empty());
        StatusText = ack.Message;
    }

    [ObservableProperty]
    private bool _secureRulesActive;

    [ObservableProperty]
    private string _secureRulesText = string.Empty;

    [RelayCommand]
    public async Task LoadSecureRulesAsync()
    {
        var status = await _client.Firewall.GetSecureRulesAsync(new Empty());
        SecureRulesActive = status.Enabled;
        SecureRulesText = status.Enabled
            ? $"Secure Rules ON — {status.Tracked} HostsGuard rules protected"
            : "Secure Rules OFF — HostsGuard rules are not tamper-guarded";
    }

    [RelayCommand]
    public async Task ToggleSecureRulesAsync()
    {
        var ack = await _client.Firewall.SetSecureRulesAsync(new SecureRulesRequest { Enabled = !SecureRulesActive });
        StatusText = ack.Message;
        await LoadSecureRulesAsync();
    }

    [RelayCommand]
    public async Task ToggleEncryptedDnsAsync()
    {
        Ack ack;
        if (DohBlockingActive)
        {
            ack = await _client.Firewall.UnblockEncryptedDnsAsync(new Empty());
        }
        else
        {
            ack = await _client.Firewall.BlockEncryptedDnsAsync(new DohBlockRequest());
        }

        StatusText = ack.Message;
        await LoadDohStatusAsync();
    }

    [RelayCommand]
    public async Task RefreshDohAsync()
    {
        var ack = await _client.Dns.RefreshDohIntelligenceAsync(new DohRefreshRequest
        {
            Url = DohUrl,
            Sha256 = DohSha256,
        });
        StatusText = ack.Message;
        await LoadDohStatusAsync();
    }

    // ─── Blocked services ─────────────────────────────────────────────────────

    [RelayCommand]
    public async Task LoadServicesAsync()
    {
        var list = await _client.Policy.ListServicesAsync(new Empty());
        Services.Clear();
        foreach (var s in list.Services)
        {
            Services.Add(new BlockableServiceViewModel
            {
                Name = s.Name,
                Blocked = s.Blocked,
                DomainCount = s.DomainCount,
                Note = s.Note,
            });
        }
    }

    [RelayCommand]
    public async Task ToggleServiceAsync(BlockableServiceViewModel service)
    {
        if (!service.Blocked && service.Note.Length != 0 &&
            !_confirm.Confirm($"Block {service.Name}", service.Note))
        {
            return;
        }

        var ack = await _client.Policy.ToggleServiceAsync(new ServiceToggleRequest
        {
            Service = service.Name,
            Block = !service.Blocked,
        });
        StatusText = ack.Message;
        await LoadServicesAsync();
    }

    // ─── Scheduled blocking ───────────────────────────────────────────────────

    [RelayCommand]
    public async Task LoadSchedulesAsync()
    {
        var list = await _client.Policy.GetSchedulesAsync(new Empty());
        Schedules.Clear();
        foreach (var s in list.Schedules)
        {
            Schedules.Add(ScheduleRowViewModel.From(s));
        }

        StatusText = $"{Schedules.Count} schedules";
    }

    [RelayCommand]
    public void AddSchedule() => Schedules.Add(new ScheduleRowViewModel { DaysText = "Mon,Tue,Wed,Thu,Fri" });

    [RelayCommand]
    public void RemoveSchedule(ScheduleRowViewModel row) => Schedules.Remove(row);

    [RelayCommand]
    public async Task SaveSchedulesAsync()
    {
        var list = new ScheduleList();
        foreach (var row in Schedules)
        {
            var schedule = new Schedule { Target = row.Target.Trim(), Start = row.Start.Trim(), End = row.End.Trim() };
            schedule.Days.AddRange(row.ParseDays());
            list.Schedules.Add(schedule);
        }

        var ack = await _client.Policy.SetSchedulesAsync(list);
        StatusText = ack.Message;
        if (ack.Ok)
        {
            await LoadSchedulesAsync();
        }
    }
}
