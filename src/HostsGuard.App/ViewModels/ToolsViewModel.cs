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

/// <summary>Row VM for the AI-knowledge review panel (NET-107).</summary>
public sealed partial class KnowledgeEntryViewModel : ObservableObject
{
    [ObservableProperty]
    private string _kind = string.Empty;   // "purpose" | "category" | "connection"

    [ObservableProperty]
    private string _key = string.Empty;    // domain, or host/ip

    [ObservableProperty]
    private string _value = string.Empty;  // AI-learned label

    [ObservableProperty]
    private string _editValue = string.Empty; // editable before promoting

    [ObservableProperty]
    private string _userOverride = string.Empty; // "" until promoted/corrected

    [ObservableProperty]
    private string _created = string.Empty;

    [ObservableProperty]
    private bool _isNew;

    public string CreatedText => TimeText.Compact(Created);
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
    [NotifyCanExecuteChangedFor(nameof(InspectCommand))]
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
    [NotifyCanExecuteChangedFor(nameof(RestoreBackupCommand))]
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

    [RelayCommand(CanExecute = nameof(CanRestoreBackup))]
    public async Task RestoreBackupAsync()
    {
        if (SelectedBackup is null)
        {
            StatusText = "Choose a backup before restoring.";
            return;
        }

        if (!_confirm.Confirm("Restore hosts backup",
            $"Replace the live hosts file with '{SelectedBackup.FileName}'? HostsGuard will write the selected backup immediately."))
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

    private bool CanRestoreBackup() => SelectedBackup is not null;

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

    [RelayCommand(CanExecute = nameof(CanInspect))]
    public async Task InspectAsync()
    {
        var result = await _client.Dns.InspectAsync(new DomainRequest { Domain = InspectDomain.Trim() });
        var records = result.Records.Count == 0
            ? "no records"
            : string.Join("; ", result.Records.Select(r => $"{r.Type} {r.Value}"));
        InspectResult = $"{(result.Blocked ? "BLOCKED" : "reachable")} — {records} ({result.LatencyMs} ms)";
    }

    private bool CanInspect() => !string.IsNullOrWhiteSpace(InspectDomain);

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
            "Reset the hosts file to Windows defaults? This removes every HostsGuard hosts-file block immediately."))
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
    [NotifyCanExecuteChangedFor(nameof(SwitchProfileCommand))]
    [NotifyCanExecuteChangedFor(nameof(DeleteProfileCommand))]
    private string? _selectedProfile;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveProfileCommand))]
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

    [RelayCommand(CanExecute = nameof(CanSaveProfile))]
    public async Task SaveProfileAsync()
    {
        var ack = await _client.Policy.SaveProfileAsync(new ProfileRequest { Name = NewProfileName.Trim() });
        StatusText = ack.Message;
        if (ack.Ok)
        {
            NewProfileName = string.Empty;
            await LoadProfilesAsync();
        }
    }

    private bool CanSaveProfile() => !string.IsNullOrWhiteSpace(NewProfileName);

    private bool CanUseSelectedProfile() => !string.IsNullOrWhiteSpace(SelectedProfile);

    [RelayCommand(CanExecute = nameof(CanUseSelectedProfile))]
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

    [RelayCommand(CanExecute = nameof(CanUseSelectedProfile))]
    public async Task DeleteProfileAsync()
    {
        if (string.IsNullOrEmpty(SelectedProfile) ||
            !_confirm.Confirm("Delete network profile",
                $"Delete network profile '{SelectedProfile}'? Saved firewall and hosts policy snapshots for this profile will be removed."))
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
    [NotifyPropertyChangedFor(nameof(SeeEverythingActive))]
    private bool _dohBlockingActive;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SeeEverythingActive))]
    private bool _quicBlockingActive;

    [ObservableProperty]
    private bool _cnameCloakActive;

    /// <summary>TLS SNI capture is running (NET-109).</summary>
    [ObservableProperty]
    private bool _sniCaptureActive;

    /// <summary>
    /// "See everything": both QUIC/UDP-443 and the DoH bootstrap blocks are on, so
    /// browsers doing their own encrypted DNS fall back to the OS resolver and the
    /// activity feed can see — and block — what they load.
    /// </summary>
    public bool SeeEverythingActive => DohBlockingActive && QuicBlockingActive;

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
        SniCaptureActive = status.SniCapture;
        DohStatusText = status.Updated.Length != 0
            ? $"DoH intelligence: {status.ResolverIps} resolver IPs; {status.Source}; updated {status.Updated}"
            : $"DoH intelligence: {status.ResolverIps} built-in resolver IPs; no refresh yet";
    }

    /// <summary>
    /// One-click coverage: turn the QUIC/UDP-443 and DoH-bootstrap blocks on (or
    /// off) together. With them on, a browser's own DoH/DoH3 can't reach its
    /// resolver, so it falls back to the OS resolver — which HostsGuard's ETW feed
    /// sees and the hosts file can block. This is the fix for "ads load but never
    /// show up in the feed."
    /// </summary>
    [RelayCommand]
    public async Task ToggleSeeEverythingAsync()
    {
        if (SeeEverythingActive)
        {
            if (QuicBlockingActive)
            {
                await _client.Firewall.UnblockQuicAsync(new Empty());
            }

            if (DohBlockingActive)
            {
                await _client.Firewall.UnblockEncryptedDnsAsync(new Empty());
            }

            StatusText = "See-everything OFF — QUIC + DoH blocking removed";
        }
        else
        {
            if (!QuicBlockingActive)
            {
                await _client.Firewall.BlockQuicAsync(new Empty());
            }

            if (!DohBlockingActive)
            {
                await _client.Firewall.BlockEncryptedDnsAsync(new DohBlockRequest());
            }

            StatusText = "See-everything ON — browser DNS forced onto the OS resolver so the feed can see it";
        }

        await LoadDohStatusAsync();
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

    /// <summary>Toggle driver-free TLS SNI capture (NET-109).</summary>
    [RelayCommand]
    public async Task ToggleSniCaptureAsync()
    {
        var ack = await _client.Dns.SetSniCaptureAsync(new SniCaptureRequest { Enabled = !SniCaptureActive });
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

        StatusText = Plural.Of(Schedules.Count, "schedule");
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

    // ─── AI categorization (DeepSeek) ─────────────────────────────────────────

    /// <summary>Pushed from the API-key PasswordBox before commands run (no binding).</summary>
    public string AiApiKey { get; set; } = string.Empty;

    [ObservableProperty]
    private string _aiModel = "deepseek-chat";

    [ObservableProperty]
    private bool _aiEnabled;

    [ObservableProperty]
    private string _aiStatusText = "Checking AI configuration…";

    public async Task LoadAiStatusAsync()
    {
        var status = await _client.Hosts.GetAiStatusAsync(new Empty());
        AiEnabled = status.Enabled;
        if (status.Model.Length != 0)
        {
            AiModel = status.Model;
        }

        AiStatusText = !status.Configured
            ? "No DeepSeek API key stored — add one to categorize domains with AI."
            : $"DeepSeek key stored · {status.Model} · auto-categorize {(status.Enabled ? "on" : "off")}"
              + (status.LastRun.Length != 0 ? $" · last run {TimeText.Compact(status.LastRun)} ({status.LastResult})" : string.Empty);
    }

    [RelayCommand]
    public async Task SaveAiConfigAsync()
    {
        var ack = await _client.Hosts.SetAiConfigAsync(new AiConfig
        {
            ApiKey = AiApiKey,
            Model = AiModel.Trim(),
            Endpoint = string.Empty, // keep the default endpoint
            Enabled = AiEnabled,
        });
        AiApiKey = string.Empty;
        StatusText = ack.Message;
        await LoadAiStatusAsync();
    }

    [RelayCommand]
    public async Task CategorizeAllAsync()
    {
        AiStatusText = "Asking DeepSeek to categorize uncategorized blocked domains…";
        var result = await _client.Hosts.CategorizeDomainsAsync(
            new CategorizeRequest { AllUncategorized = true });
        StatusText = result.Message;
        await LoadAiStatusAsync();
    }

    /// <summary>
    /// Save everything the AI has learned (purposes, categories, connection
    /// info) to a user-readable JSON file — the review path for promoting
    /// entries into the app's curated built-ins.
    /// </summary>
    [RelayCommand]
    public async Task ExportAiKnowledgeAsync()
    {
        var payload = await _client.Hosts.ExportAiKnowledgeAsync(new Empty());
        var dir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HostsGuard");
        var path = System.IO.Path.Combine(dir, "ai_knowledge.json");
        try
        {
            System.IO.Directory.CreateDirectory(dir);
            await System.IO.File.WriteAllTextAsync(path, payload.Text);
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
            // A file error must not reach the global handler, which would
            // misreport it as a lost service connection.
            StatusText = $"Couldn't write the knowledge log: {ex.Message}";
            return;
        }

        StatusText = $"AI knowledge exported to {path}";
        AiStatusText = $"Knowledge log saved: {path}";
    }

    // ─── AI-knowledge review & promote (NET-107) ─────────────────────────────

    public ObservableCollection<KnowledgeEntryViewModel> Knowledge { get; } = new();

    [ObservableProperty]
    private bool _knowledgeOnlyNew = true;

    [ObservableProperty]
    private string _knowledgeStatusText = "Load what the AI has learned to review it.";

    // Inline "correct a domain" mini-form (the remembered correction path).
    [ObservableProperty]
    private string _correctDomain = string.Empty;

    [ObservableProperty]
    private string _correctKind = "category"; // "category" | "purpose"

    [ObservableProperty]
    private string _correctValue = string.Empty;

    public static IReadOnlyList<string> CorrectionKinds { get; } = new[] { "category", "purpose" };

    [RelayCommand]
    public async Task LoadKnowledgeAsync()
    {
        var list = await _client.Hosts.ListAiKnowledgeAsync(new AiKnowledgeRequest { SinceLastReview = KnowledgeOnlyNew });
        Knowledge.Clear();
        foreach (var e in list.Entries.OrderByDescending(e => e.Created))
        {
            Knowledge.Add(new KnowledgeEntryViewModel
            {
                Kind = e.Kind,
                Key = e.Key,
                Value = e.Value,
                EditValue = e.UserOverride.Length != 0 ? e.UserOverride : e.Value,
                UserOverride = e.UserOverride,
                Created = e.Created,
                IsNew = e.IsNew,
            });
        }

        KnowledgeStatusText = Knowledge.Count == 0
            ? (KnowledgeOnlyNew ? "Nothing new learned since your last review." : "The AI hasn't learned anything yet.")
            : $"{Plural.Of(Knowledge.Count, "learned entry", "learned entries")}"
              + (list.LastReviewed.Length != 0 ? $" · last review {TimeText.Compact(list.LastReviewed)}" : " · never reviewed");
    }

    [RelayCommand]
    public async Task PromoteKnowledgeAsync(KnowledgeEntryViewModel row)
    {
        if (row is null)
        {
            return;
        }

        var request = new KnowledgeReviewRequest();
        request.Actions.Add(new KnowledgeReviewAction { Kind = row.Kind, Key = row.Key, Action = "promote", Value = row.EditValue });
        var ack = await _client.Hosts.PromoteKnowledgeAsync(request);
        StatusText = ack.Message;
        await LoadKnowledgeAsync();
    }

    [RelayCommand]
    public async Task DiscardKnowledgeAsync(KnowledgeEntryViewModel row)
    {
        if (row is null)
        {
            return;
        }

        var request = new KnowledgeReviewRequest();
        request.Actions.Add(new KnowledgeReviewAction { Kind = row.Kind, Key = row.Key, Action = "discard" });
        var ack = await _client.Hosts.PromoteKnowledgeAsync(request);
        StatusText = ack.Message;
        await LoadKnowledgeAsync();
    }

    [RelayCommand]
    public async Task MarkKnowledgeReviewedAsync()
    {
        var ack = await _client.Hosts.PromoteKnowledgeAsync(new KnowledgeReviewRequest { MarkReviewed = true });
        StatusText = ack.Message;
        await LoadKnowledgeAsync();
    }

    [RelayCommand]
    public async Task CorrectDomainAsync()
    {
        var domain = CorrectDomain.Trim();
        if (domain.Length == 0)
        {
            StatusText = "Enter a domain to correct.";
            return;
        }

        var ack = await _client.Hosts.OverrideKnowledgeAsync(new KnowledgeOverrideRequest
        {
            Kind = CorrectKind,
            Key = domain,
            Value = CorrectValue.Trim(),
        });
        StatusText = ack.Message;
        CorrectValue = string.Empty;
        await LoadKnowledgeAsync();
    }

    // ─── Blocklist intelligence ───────────────────────────────────────────────

    [ObservableProperty]
    private string _intelStatusText = "Checking blocklist intelligence…";

    public async Task LoadIntelStatusAsync()
    {
        var status = await _client.Lists.GetBlocklistIntelligenceAsync(new Empty());
        IntelStatusText = status.Refreshing
            ? "Downloading reference blocklists in the background…"
            : status.Lists == 0
                ? "No reference lists downloaded yet — refresh to build the block-candidate index."
                : $"{Plural.Of(status.Lists, "reference list")} · {status.Domains:N0} domains indexed"
                  + (status.Refreshed.Length != 0 ? $" · refreshed {TimeText.Compact(status.Refreshed)}" : string.Empty);
    }

    [RelayCommand]
    public async Task RefreshIntelAsync()
    {
        IntelStatusText = "Downloading reference blocklists — this can take a few minutes…";
        var ack = await _client.Lists.RefreshBlocklistIntelligenceAsync(new Empty());
        StatusText = ack.Message;
        await LoadIntelStatusAsync();
    }
}
