using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using HostsGuard.App.Services;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.App.ViewModels;

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
        (I18n.T("Dns_ResolverDhcpDefault", "DHCP (default)"), Array.Empty<string>()),
        ("Cloudflare (1.1.1.1)", new[] { "1.1.1.1", "1.0.0.1" }),
        ("Google (8.8.8.8)", new[] { "8.8.8.8", "8.8.4.4" }),
        ("Quad9 (9.9.9.9)", new[] { "9.9.9.9", "149.112.112.112" }),
    };

    private readonly HostsServiceClient _client;
    private readonly IConfirm _confirm;

    [ObservableProperty]
    private string _statusText = I18n.T("Status.Ready", "Ready");

    [ObservableProperty]
    private string _selectedResolver = I18n.T("Dns_ResolverDhcpDefault", "DHCP (default)");

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

    public ObservableCollection<DnsCacheEntryViewModel> DnsCacheEntries { get; } = new();

    public ObservableCollection<ServiceBindingRecordViewModel> ServiceBindings { get; } = new();

    public ObservableCollection<DnsAdapterRowViewModel> DnsAdapters { get; } = new();

    public ObservableCollection<PolicySubscriptionViewModel> PolicySubscriptions { get; } = new();

    public ObservableCollection<LanAttackSurfaceToggleViewModel> LanAttackSurface { get; } = new();

    public ObservableCollection<AppVpnBindingRowViewModel> AppVpnBindings { get; } = new();

    public ObservableCollection<SecureRuleConflictRowViewModel> SecureRuleConflicts { get; } = new();

    public static IReadOnlyList<string> ResolverNames { get; } = ResolverPresets.Select(p => p.Name).ToList();

    [RelayCommand]
    public async Task FlushDnsAsync()
    {
        await RunServiceActionAsync(I18n.T("Tools_ActionFlushDns", "Flush DNS cache"), async () =>
        {
            var ack = await _client.Dns.FlushCacheAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    // ─── Settings lock (NET-079) ─────────────────────────────────────────────

    [ObservableProperty]
    private string _dnsCacheSearch = string.Empty;

    [ObservableProperty]
    private int _dnsCacheLimit = 500;

    [ObservableProperty]
    private string _dnsCacheStatusText = I18n.T("DnsCache_StatusHint", "Load DNS cache entries to verify what Windows is still resolving locally.");

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(FlushDnsCacheEntryCommand))]
    private DnsCacheEntryViewModel? _selectedDnsCacheEntry;

    [RelayCommand]
    public async Task LoadDnsCacheAsync()
    {
        await RunServiceActionAsync(I18n.T("DnsCache_ActionLoad", "Load DNS cache"), s => DnsCacheStatusText = s, LoadDnsCacheCoreAsync);
    }

    [RelayCommand(CanExecute = nameof(CanFlushDnsCacheEntry))]
    public async Task FlushDnsCacheEntryAsync()
    {
        if (SelectedDnsCacheEntry is not { } row)
        {
            DnsCacheStatusText = I18n.T("DnsCache_SelectFirst", "Select a cached DNS entry first.");
            return;
        }

        await RunServiceActionAsync(I18n.T("DnsCache_ActionFlushEntry", "Flush DNS cache entry"), s => DnsCacheStatusText = s, async () =>
        {
            var ack = await _client.Dns.FlushCacheEntryAsync(new DnsCacheEntryRequest { Name = row.Name });
            StatusText = ack.Message;
            DnsCacheStatusText = ack.Message;
            if (ack.Ok)
            {
                await LoadDnsCacheCoreAsync();
            }
        });
    }

    private bool CanFlushDnsCacheEntry() => SelectedDnsCacheEntry is not null;

    private async Task LoadDnsCacheCoreAsync()
    {
        DnsCacheLimit = Math.Clamp(DnsCacheLimit, 1, 2_000);
        var list = await _client.Dns.ListCacheAsync(new DnsCacheRequest
        {
            Limit = DnsCacheLimit,
            Search = DnsCacheSearch.Trim(),
        });

        DnsCacheEntries.Clear();
        foreach (var entry in list.Entries.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
        {
            DnsCacheEntries.Add(DnsCacheEntryViewModel.From(entry));
        }

        SelectedDnsCacheEntry = DnsCacheEntries.FirstOrDefault();
        var https = DnsCacheEntries.Count(e => e.Type.Equals("HTTPS", StringComparison.OrdinalIgnoreCase));
        var svcb = DnsCacheEntries.Count(e => e.Type.Equals("SVCB", StringComparison.OrdinalIgnoreCase));
        DnsCacheStatusText = https + svcb == 0
            ? list.Message
            : I18n.T("DnsCache_Status", "{0}; HTTPS/SVCB: {1} HTTPS, {2} SVCB. Windows cache does not expose ECH SVCB parameters.", list.Message, https, svcb);
    }

    [RelayCommand]
    public async Task LoadLockStateAsync()
    {
        await RunServiceActionAsync(I18n.T("SettingsLock_ActionLoad", "Load settings lock state"), s => LockStatus = s, async () =>
        {
            var state = await _client.Policy.GetLockStateAsync(new Empty());
            LockEnabled = state.Enabled;
            LockStatus = state.Degraded
                ? I18n.T("SettingsLock_RecoveryRequired",
                    "Recovery required — lock state is unreadable. Stop HostsGuardSvc as an administrator, remove lock_state.json from the HostsGuard ProgramData directory, and restart the service.")
                : state.RetryAfterSeconds > 0
                    ? I18n.T("SettingsLock_AttemptsPaused",
                        "Locked — password attempts paused for {0} seconds after {1} failures",
                        state.RetryAfterSeconds,
                        state.FailedAttempts)
                    : state.Enabled
                        ? state.Unlocked
                            ? I18n.T("SettingsLock_TemporarilyUnlocked", "Locked (temporarily unlocked)")
                            : I18n.T("SettingsLock_Locked", "Locked")
                        : I18n.T("SettingsLock_NotLocked", "Not locked");
        });
    }

    [RelayCommand]
    public async Task EnableLockAsync()
    {
        await RunServiceActionAsync(I18n.T("SettingsLock_ActionEnable", "Enable settings lock"), s => LockStatus = s, async () =>
        {
            var ack = await _client.Policy.SetLockAsync(new LockRequest { Action = "enable", Password = LockPassword });
            LockStatus = ack.Message;
            LockPassword = string.Empty;
            if (ack.Ok)
            {
                await LoadLockStateAsync();
            }
        });
    }

    [RelayCommand]
    public async Task DisableLockAsync()
    {
        await RunServiceActionAsync(I18n.T("SettingsLock_ActionDisable", "Disable settings lock"), s => LockStatus = s, async () =>
        {
            var ack = await _client.Policy.SetLockAsync(new LockRequest { Action = "disable", Password = LockPassword });
            LockStatus = ack.Message;
            LockPassword = string.Empty;
            if (ack.Ok)
            {
                await LoadLockStateAsync();
            }
        });
    }

    [RelayCommand]
    public async Task UnlockAsync()
    {
        await RunServiceActionAsync(I18n.T("SettingsLock_ActionUnlock", "Unlock settings"), s => LockStatus = s, async () =>
        {
            var ack = await _client.Policy.UnlockAsync(new LockRequest { Password = LockPassword, Minutes = UnlockMinutes });
            LockStatus = ack.Message;
            LockPassword = string.Empty;
            if (ack.Ok)
            {
                await LoadLockStateAsync();
            }
        });
    }

    [RelayCommand]
    public async Task ProtectHostsAsync()
    {
        await RunServiceActionAsync(I18n.T("Tools_ActionProtectHosts", "Protect hosts file"), async () =>
        {
            var ack = await _client.Policy.SetHostsProtectionAsync(new HostsProtectionRequest { Enabled = true });
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task ApplyResolverAsync()
    {
        await RunServiceActionAsync(I18n.T("Dns_ActionApplyResolver", "Apply DNS resolver"), async () =>
        {
            var preset = ResolverPresets.FirstOrDefault(p => p.Name == SelectedResolver);
            var request = new ResolverRequest();
            request.Servers.AddRange(preset.Servers ?? Array.Empty<string>());
            request.AdapterIds.AddRange(DnsAdapters.Where(adapter => adapter.IsSelected).Select(adapter => adapter.Id));
            if (request.AdapterIds.Count == 0)
            {
                StatusText = I18n.T("Dns_SelectAdapter", "Select at least one DNS adapter. VPN/tunnel adapters are never changed implicitly.");
                return;
            }

            var ack = await _client.Dns.SetResolverAsync(request);
            StatusText = ack.Message;
            await LoadDnsAdaptersCoreAsync();
        });
    }

    [RelayCommand]
    public async Task LoadDnsAdaptersAsync()
    {
        await RunServiceActionAsync(I18n.T("Dns_ActionLoadAdapters", "Load DNS adapters"), LoadDnsAdaptersCoreAsync);
    }

    private async Task LoadDnsAdaptersCoreAsync()
    {
        var response = await _client.Dns.ListResolverAdaptersAsync(new Empty());
        var selected = DnsAdapters.Where(adapter => adapter.IsSelected)
            .Select(adapter => adapter.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        DnsAdapters.Clear();
        foreach (var adapter in response.Adapters)
        {
            var row = DnsAdapterRowViewModel.From(adapter);
            if (selected.Count != 0)
            {
                row.IsSelected = selected.Contains(row.Id);
            }

            DnsAdapters.Add(row);
        }
    }

    [RelayCommand]
    public async Task BackupHostsAsync()
    {
        await RunServiceActionAsync(I18n.T("Backup_ActionCreate", "Back up hosts file"), async () =>
        {
            var ack = await _client.Hosts.BackupHostsAsync(new Empty());
            StatusText = ack.Ok ? I18n.T("Backup_Written", "Backup written: {0}", ack.Message) : ack.Message;
            await LoadBackupsAsync();
        });
    }

    // ─── Backup restore ───────────────────────────────────────────────────────

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RestoreBackupCommand))]
    private BackupRowViewModel? _selectedBackup;

    public ObservableCollection<BackupRowViewModel> Backups { get; } = new();

    [RelayCommand]
    public async Task LoadBackupsAsync()
    {
        await RunServiceActionAsync(I18n.T("Backup_ActionLoad", "Load hosts backups"), async () =>
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
        });
    }

    [RelayCommand(CanExecute = nameof(CanRestoreBackup))]
    public async Task RestoreBackupAsync()
    {
        if (SelectedBackup is null)
        {
            StatusText = I18n.T("Backup_SelectFirst", "Choose a backup before restoring.");
            return;
        }

        if (!_confirm.Confirm(I18n.T("Backup_RestoreTitle", "Restore hosts backup"),
            I18n.T("Backup_RestoreMessage", "Replace the live hosts file with '{0}'? HostsGuard will write the selected backup immediately.", SelectedBackup.FileName)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Backup_ActionRestore", "Restore hosts backup"), async () =>
        {
            var ack = await _client.Hosts.RestoreBackupAsync(new BackupRequest { FileName = SelectedBackup.FileName });
            StatusText = ack.Message;
            if (ack.Ok)
            {
                await LoadBackupsAsync();
            }
        });
    }

    private bool CanRestoreBackup() => SelectedBackup is not null;

    [RelayCommand]
    public async Task HardenAclAsync()
    {
        await RunServiceActionAsync(I18n.T("Tools_ActionHardenAcl", "Harden hosts ACL"), async () =>
        {
            var ack = await _client.Hosts.HardenAclAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task ExportBundleAsync()
    {
        await RunServiceActionAsync(I18n.T("Support_ActionExport", "Export support bundle"), async () =>
        {
            var ack = await _client.Diagnostics.ExportSupportBundleAsync(new SupportBundleRequest());
            StatusText = ack.Ok ? I18n.T("Support_Exported", "Support bundle: {0}", ack.Message) : ack.Message;
        });
    }

    [RelayCommand(CanExecute = nameof(CanInspect))]
    public async Task InspectAsync()
    {
        await RunServiceActionAsync(I18n.T("Inspect_ActionDomain", "Inspect domain"), s => InspectResult = s, async () =>
        {
            var result = await _client.Dns.InspectAsync(new DomainRequest { Domain = InspectDomain.Trim() });
            ServiceBindings.Clear();
            foreach (var binding in result.ServiceBindings)
            {
                ServiceBindings.Add(ServiceBindingRecordViewModel.From(binding));
            }

            var records = result.Records.Count == 0
                ? I18n.T("Inspect_NoRecords", "no records")
                : string.Join("; ", result.Records.Select(r => $"{r.Type} {r.Value}"));
            var ech = string.IsNullOrWhiteSpace(result.EchSummary)
                ? string.Empty
                : I18n.T("Inspect_EchSuffix", " | Service-wide ECH visibility (not attributable to this domain): {0} {1}", result.EchSummary, result.EchRemediation);
            InspectResult = I18n.T("Inspect_Result", "{0} - {1} ({2} ms){3}",
                result.Blocked ? I18n.T("Inspect_Blocked", "BLOCKED") : I18n.T("Inspect_Reachable", "reachable"), records, result.LatencyMs, ech);
            ServiceBindingStatusText = !result.ServiceBindingQueryAvailable
                ? I18n.T("ServiceBinding_Unavailable", "Direct HTTPS/SVCB inspection unavailable: {0}", result.ServiceBindingMessage)
                : I18n.T("ServiceBinding_Status",
                    "{0} direct record(s). ECH advertised by this name={1}; ECH observed locally={2} ({3} global observation(s), not attributable to this name). {4}",
                    result.ServiceBindings.Count,
                    result.EchAdvertised ? I18n.T("Common_Yes", "yes") : I18n.T("Common_No", "no"),
                    result.EchObserved ? I18n.T("Common_Yes", "yes") : I18n.T("Common_No", "no"),
                    result.EchObservationCount,
                    result.ServiceBindingMessage);
        });
    }

    [ObservableProperty]
    private string _serviceBindingStatusText = I18n.T("ServiceBinding_StatusHint",
        "Inspect a domain to query HTTPS/SVCB records directly. ECH advertisement is not proof that an ECH connection occurred.");

    private bool CanInspect() => !string.IsNullOrWhiteSpace(InspectDomain);

    [ObservableProperty]
    private string _defenderStatusText = string.Empty;

    [RelayCommand]
    public async Task LoadDefenderStatusAsync()
    {
        await RunServiceActionAsync(I18n.T("Defender_ActionLoad", "Load Defender status"), s => DefenderStatusText = s, async () =>
        {
            var status = await _client.Diagnostics.GetDefenderStatusAsync(new Empty());
            DefenderStatusText = !status.Available
                ? I18n.T("Defender_NotAccessible", "Defender: not accessible")
                : status.HostsExcluded
                    ? I18n.T("Defender_Excluded", "Defender: hosts file is excluded")
                    : status.PossibleRevert
                        ? I18n.T("Defender_RevertLikely", "Defender: hosts file NOT excluded — blocks are missing (possible Defender revert)")
                        : I18n.T("Defender_NotExcluded", "Defender: hosts file not excluded (HostsFileHijack detection may remove telemetry blocks)");
        });
    }

    [RelayCommand]
    public async Task AddDefenderExclusionAsync()
    {
        await RunServiceActionAsync(I18n.T("Defender_ActionExclude", "Add Defender exclusion"), async () =>
        {
            var ack = await _client.Hosts.AddDefenderExclusionAsync(new Empty());
            StatusText = ack.Message;
            await LoadDefenderStatusAsync();
        });
    }

    [RelayCommand]
    public async Task RefreshThreatIntelAsync()
    {
        await RunServiceActionAsync(I18n.T("ThreatIntel_ActionRefresh", "Refresh threat intelligence"), async () =>
        {
            StatusText = I18n.T("ThreatIntel_Refreshing", "Refreshing threat intelligence…");
            var ack = await _client.Lists.RefreshThreatIntelAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task RefreshGeoIpAsync()
    {
        await RunServiceActionAsync(I18n.T("GeoIp_ActionRefresh", "Refresh GeoIP database"), async () =>
        {
            StatusText = I18n.T("GeoIp_Downloading", "Downloading GeoIP database…");
            var ack = await _client.Lists.RefreshGeoIpAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task EmergencyResetAsync()
    {
        if (!_confirm.Confirm(I18n.T("Tools_EmergencyResetTitle", "Emergency reset"),
            I18n.T("Tools_EmergencyResetMessage", "Reset the hosts file to Windows defaults? This removes every HostsGuard hosts-file block immediately.")))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Tools_ActionEmergencyReset", "Emergency reset hosts file"), async () =>
        {
            var ack = await _client.Hosts.EmergencyResetAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    // ─── Network profiles ─────────────────────────────────────────────────────

    [ObservableProperty]
    private string _activeProfile = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SwitchProfileCommand))]
    [NotifyCanExecuteChangedFor(nameof(DeleteProfileCommand))]
    [NotifyCanExecuteChangedFor(nameof(SaveNetworkProfileRuleCommand))]
    private string? _selectedProfile;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveProfileCommand))]
    private string _newProfileName = string.Empty;

    public ObservableCollection<string> Profiles { get; } = new();

    [RelayCommand]
    public async Task LoadProfilesAsync()
    {
        await RunServiceActionAsync(I18n.T("Profile_ActionLoad", "Load network profiles"), async () =>
        {
            var list = await _client.Policy.ListProfilesAsync(new Empty());
            Profiles.Clear();
            foreach (var name in list.Names)
            {
                Profiles.Add(name);
            }

            ActiveProfile = list.Active.Length != 0
                ? I18n.T("Profile_Active", "Active: {0}", list.Active)
                : I18n.T("Profile_NoneActive", "No active profile");
            SelectedProfile = list.Names.Contains(list.Active) ? list.Active : Profiles.FirstOrDefault();
        });
    }

    [RelayCommand(CanExecute = nameof(CanSaveProfile))]
    public async Task SaveProfileAsync()
    {
        await RunServiceActionAsync(I18n.T("Profile_ActionSave", "Save network profile"), async () =>
        {
            var ack = await _client.Policy.SaveProfileAsync(new ProfileRequest { Name = NewProfileName.Trim() });
            StatusText = ack.Message;
            if (ack.Ok)
            {
                NewProfileName = string.Empty;
                await LoadProfilesAsync();
            }
        });
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

        var warning = await RemoteSessionWarning.DescribeAsync(_client);
        if (warning.Length != 0 && !_confirm.Confirm(
                I18n.T("Profile_RemoteSwitchTitle", "Switch network profile during Remote Desktop use"),
                RemoteSessionWarning.AppendTo(
                    I18n.T("Profile_RemoteSwitchMessage", "Switch to network profile '{0}'? Its saved policy may change firewall or hosts enforcement.", SelectedProfile),
                    warning)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Profile_ActionSwitch", "Switch network profile"), async () =>
        {
            var ack = await _client.Policy.SwitchProfileAsync(new ProfileRequest { Name = SelectedProfile });
            StatusText = ack.Message;
            await LoadProfilesAsync();
        });
    }

    [RelayCommand(CanExecute = nameof(CanUseSelectedProfile))]
    public async Task DeleteProfileAsync()
    {
        if (string.IsNullOrEmpty(SelectedProfile) ||
            !_confirm.Confirm(I18n.T("Profile_DeleteTitle", "Delete network profile"),
                I18n.T("Profile_DeleteMessage", "Delete network profile '{0}'? Saved firewall and hosts policy snapshots for this profile will be removed.", SelectedProfile)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Profile_ActionDelete", "Delete network profile"), async () =>
        {
            var ack = await _client.Policy.DeleteProfileAsync(new ProfileRequest { Name = SelectedProfile });
            StatusText = ack.Message;
            await LoadProfilesAsync();
        });
    }

    // ─── Encrypted DNS (DoH/DoT) ──────────────────────────────────────────────

    [ObservableProperty]
    private string _dohStatusText = string.Empty;

    [ObservableProperty]
    private string _echPostureText = I18n.T("Ech_StatusHint", "Load encrypted DNS status to review HTTPS/SVCB and ECH visibility.");

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

    /// <summary>OS is in encrypted-DNS-only posture — warn before blocking DoH (NET-112).</summary>
    [ObservableProperty]
    private bool _dnsEncryptedOnly;

    /// <summary>Windows DNR is on: the network can auto-provision an encrypted resolver (NET-173).</summary>
    [ObservableProperty]
    private bool _dnrEnabled;

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
        await RunServiceActionAsync(I18n.T("EncryptedDns_ActionLoad", "Load encrypted DNS status"), s => DohStatusText = s, async () =>
        {
            var status = await _client.Dns.GetDohStatusAsync(new Empty());
            DohBlockingActive = status.BlockingActive;
            QuicBlockingActive = status.QuicBlocked;
            CnameCloakActive = status.CnameCloak;
            SniCaptureActive = status.SniCapture;
            DnsEncryptedOnly = status.DnsEncryptedOnly;
            DnrEnabled = status.DnrEnabled;
            var serviceBindings = I18n.T("EncryptedDns_CacheRows", "{0} HTTPS / {1} SVCB cache rows", status.HttpsRecords, status.SvcbRecords);
            var dnrNote = status.DnrEnabled ? I18n.T("EncryptedDns_DnrSuffix", "; DNR on (network may auto-provision an encrypted resolver)") : string.Empty;
            DohStatusText = (status.Updated.Length != 0
                ? I18n.T("EncryptedDns_IntelUpdated", "DoH intelligence: {0} resolver IPs; {1}; updated {2}; {3}", status.ResolverIps, status.Source, status.Updated, serviceBindings)
                : I18n.T("EncryptedDns_IntelBuiltin", "DoH intelligence: {0} built-in resolver IPs; no refresh yet; {1}", status.ResolverIps, serviceBindings)) + dnrNote;
            EchPostureText = string.IsNullOrWhiteSpace(status.EchSummary)
                ? I18n.T("Ech_Unavailable", "ECH posture unavailable.")
                : I18n.T("Ech_Posture", "{0} {1}", status.EchSummary, status.EchRemediation);
        });
    }

    /// <summary>
    /// One-click coverage: turn the QUIC/UDP-443 and DoH-bootstrap blocks on (or
    /// off) together. With them on, a browser's own DoH/DoH3 can't reach its
    /// resolver, so it falls back to the OS resolver — which HostsGuard's ETW feed
    /// sees and the hosts file can block. This is the fix for "ads load but never
    /// show up in the feed."
    /// </summary>
    /// <summary>
    /// NET-112: on an encrypted-DNS-only machine, blocking DoH can sever name
    /// resolution if the resolver changes (the current one is exempted). Warn
    /// before arming. Returns false to abort.
    /// </summary>
    private bool ConfirmDohBlockArm()
        => !DnsEncryptedOnly || _confirm.Confirm(I18n.T("EncryptedDns_OnlyTitle", "Encrypted-DNS-only system detected"),
            I18n.T("EncryptedDns_OnlyMessage", "Your system is set to require encrypted DNS with no plaintext fallback. HostsGuard exempts your current resolver, but blocking encrypted DNS could break name resolution if your DNS server changes. Continue?"));

    [RelayCommand]
    public async Task ToggleSeeEverythingAsync()
    {
        if (!SeeEverythingActive && !ConfirmDohBlockArm())
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Visibility_ActionToggle", "Toggle see-everything mode"), async () =>
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

                StatusText = I18n.T("Visibility_Off", "See-everything OFF — QUIC + DoH blocking removed");
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

                StatusText = I18n.T("Visibility_On", "See-everything ON — browser DNS forced onto the OS resolver so the feed can see it");
            }

            await LoadDohStatusAsync();
        });
    }

    [RelayCommand]
    public async Task ToggleQuicAsync()
    {
        await RunServiceActionAsync(I18n.T("Quic_ActionToggle", "Toggle QUIC blocking"), async () =>
        {
            var ack = QuicBlockingActive
                ? await _client.Firewall.UnblockQuicAsync(new Empty())
                : await _client.Firewall.BlockQuicAsync(new Empty());
            StatusText = ack.Message;
            await LoadDohStatusAsync();
        });
    }

    [RelayCommand]
    public async Task ToggleCnameCloakAsync()
    {
        await RunServiceActionAsync(I18n.T("Cname_ActionToggle", "Toggle CNAME cloak detection"), async () =>
        {
            var ack = await _client.Dns.SetCnameCloakAsync(new CnameCloakRequest { Enabled = !CnameCloakActive });
            StatusText = ack.Message;
            await LoadDohStatusAsync();
        });
    }

    /// <summary>Toggle driver-free TLS SNI capture (NET-109).</summary>
    [RelayCommand]
    public async Task ToggleSniCaptureAsync()
    {
        await RunServiceActionAsync(I18n.T("Sni_ActionToggle", "Toggle SNI capture"), async () =>
        {
            var ack = await _client.Dns.SetSniCaptureAsync(new SniCaptureRequest { Enabled = !SniCaptureActive });
            StatusText = ack.Message;
            await LoadDohStatusAsync();
        });
    }

    [RelayCommand]
    public async Task ApplyBaselineAsync()
    {
        await RunServiceActionAsync(I18n.T("Baseline_ActionApply", "Apply baseline rules"), async () =>
        {
            var ack = await _client.Consent.ApplyBaselineAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    // ─── Trusted publishers (NET-113) ────────────────────────────────────────

    public ObservableCollection<string> TrustedPublishers { get; } = new();

    [RelayCommand]
    public async Task LoadTrustedPublishersAsync()
    {
        await RunServiceActionAsync(I18n.T("Trust_ActionLoadPublishers", "Load trusted publishers"), async () =>
        {
            var list = await _client.Consent.GetTrustedPublishersAsync(new Empty());
            TrustedPublishers.Clear();
            foreach (var p in list.Publishers)
            {
                TrustedPublishers.Add(p);
            }
        });
    }

    [RelayCommand]
    public async Task RemoveTrustedPublisherAsync(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher) ||
            !_confirm.Confirm(I18n.T("Trust_RemovePublisherTitle", "Remove trusted publisher"),
                I18n.T("Trust_RemovePublisherMessage", "Stop auto-allowing software signed by \"{0}\"? Existing rules are unchanged.", publisher)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Trust_ActionRemovePublisher", "Remove trusted publisher"), async () =>
        {
            var remaining = new PublisherList();
            remaining.Publishers.AddRange(TrustedPublishers.Where(p => p != publisher));
            var ack = await _client.Consent.SetTrustedPublishersAsync(remaining);
            StatusText = ack.Message;
            await LoadTrustedPublishersAsync();
        });
    }

    // ─── Trusted folders (NET-117) ───────────────────────────────────────────

    public ObservableCollection<string> TrustedFolders { get; } = new();

    [RelayCommand]
    public async Task LoadTrustedFoldersAsync()
    {
        await RunServiceActionAsync(I18n.T("Trust_ActionLoadFolders", "Load trusted folders"), async () =>
        {
            var list = await _client.Consent.GetTrustedFoldersAsync(new Empty());
            TrustedFolders.Clear();
            foreach (var f in list.Folders)
            {
                TrustedFolders.Add(f);
            }
        });
    }

    [RelayCommand]
    public async Task RemoveTrustedFolderAsync(string folder)
    {
        if (string.IsNullOrWhiteSpace(folder) ||
            !_confirm.Confirm(I18n.T("Trust_RemoveFolderTitle", "Remove trusted folder"),
                I18n.T("Trust_RemoveFolderMessage", "Stop auto-allowing software in \"{0}\"? Existing rules are unchanged.", folder)))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Trust_ActionRemoveFolder", "Remove trusted folder"), async () =>
        {
            var remaining = new FolderList();
            remaining.Folders.AddRange(TrustedFolders.Where(f => f != folder));
            var ack = await _client.Consent.SetTrustedFoldersAsync(remaining);
            StatusText = ack.Message;
            await LoadTrustedFoldersAsync();
        });
    }

    [ObservableProperty]
    private bool _secureRulesActive;

    [ObservableProperty]
    private string _secureRulesText = string.Empty;

    [RelayCommand]
    public async Task LoadSecureRulesAsync()
    {
        await RunServiceActionAsync(I18n.T("SecureRules_ActionLoad", "Load Secure Rules status"), s => SecureRulesText = s, async () =>
        {
            var status = await _client.Firewall.GetSecureRulesAsync(new Empty());
            SecureRulesActive = status.Enabled;
            SecureRuleConflicts.Clear();
            foreach (var conflict in status.Conflicts.OrderBy(c => c.Name, StringComparer.Ordinal))
            {
                SecureRuleConflicts.Add(SecureRuleConflictRowViewModel.From(conflict));
            }

            SecureRulesText = status.Enabled
                ? status.Quarantined > 0
                    ? I18n.T("SecureRules_OnQuarantined", "Secure Rules ON — {0} protected; {1} quarantined and awaiting action", status.Tracked, status.Quarantined)
                    : I18n.T("SecureRules_On", "Secure Rules ON — {0} HostsGuard rules protected", status.Tracked)
                : status.Quarantined > 0
                    ? I18n.T("SecureRules_OffQuarantined", "Secure Rules OFF — {0} quarantined conflicts retained for review", status.Quarantined)
                    : I18n.T("SecureRules_Off", "Secure Rules OFF — HostsGuard rules are not tamper-guarded");
        });
    }

    [RelayCommand]
    public async Task ToggleSecureRulesAsync()
    {
        await RunServiceActionAsync(I18n.T("SecureRules_ActionToggle", "Toggle Secure Rules"), s => SecureRulesText = s, async () =>
        {
            var ack = await _client.Firewall.SetSecureRulesAsync(new SecureRulesRequest { Enabled = !SecureRulesActive });
            StatusText = ack.Message;
            await LoadSecureRulesAsync();
        });
    }

    [RelayCommand]
    public async Task AcceptSecureRuleConflictAsync(SecureRuleConflictRowViewModel? row)
    {
        if (row is null || !new MutationConfirmation(
                I18n.T("SecureRules_AcceptTitle", "Accept foreign firewall state"),
                I18n.T("SecureRules_ConflictTarget", "Quarantined rule: {0}", row.Name),
                I18n.T("SecureRules_AcceptConsequence", "HostsGuard will stop tracking this rule and leave its current missing or disabled state unchanged.")).Request(_confirm))
        {
            return;
        }

        await ResolveSecureRuleConflictAsync(row, "accept", I18n.T("SecureRules_ActionAccept", "Accept Secure Rules conflict"));
    }

    [RelayCommand]
    public async Task RearmSecureRuleConflictAsync(SecureRuleConflictRowViewModel? row)
    {
        if (row is null || !new MutationConfirmation(
                I18n.T("SecureRules_RearmTitle", "Re-arm firewall rule recovery"),
                I18n.T("SecureRules_ConflictTarget", "Quarantined rule: {0}", row.Name),
                I18n.T("SecureRules_RearmConsequence", "HostsGuard will immediately restore the tracked state and resume automatic recovery. Resolve external policy first to avoid another quarantine.")).Request(_confirm))
        {
            return;
        }

        await ResolveSecureRuleConflictAsync(row, "rearm", I18n.T("SecureRules_ActionRearm", "Re-arm Secure Rules conflict"));
    }

    private async Task ResolveSecureRuleConflictAsync(SecureRuleConflictRowViewModel row, string action, string actionLabel)
    {
        await RunServiceActionAsync(actionLabel, s => SecureRulesText = s, async () =>
        {
            var ack = await _client.Firewall.ResolveSecureRuleConflictAsync(new SecureRuleConflictRequest
            {
                Name = row.Name,
                Action = action,
            });
            StatusText = ack.Message;
            await LoadSecureRulesAsync();
        });
    }

    [RelayCommand]
    public async Task ToggleEncryptedDnsAsync()
    {
        if (!DohBlockingActive && !ConfirmDohBlockArm())
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("EncryptedDns_ActionToggle", "Toggle encrypted DNS blocking"), s => DohStatusText = s, async () =>
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
        });
    }

    [RelayCommand]
    public async Task RefreshDohAsync()
    {
        await RunServiceActionAsync(I18n.T("EncryptedDns_ActionRefresh", "Refresh encrypted DNS intelligence"), s => DohStatusText = s, async () =>
        {
            var ack = await _client.Dns.RefreshDohIntelligenceAsync(new DohRefreshRequest
            {
                Url = DohUrl,
                Sha256 = DohSha256,
            });
            StatusText = ack.Message;
            await LoadDohStatusAsync();
        });
    }

    // ─── Blocked services ─────────────────────────────────────────────────────

    [RelayCommand]
    public async Task LoadLanAttackSurfaceAsync()
    {
        await RunServiceActionAsync(I18n.T("Lan_ActionLoad", "Load LAN attack-surface controls"), async () =>
        {
            var status = await _client.Firewall.GetLanAttackSurfaceAsync(new Empty());
            LanAttackSurface.Clear();
            foreach (var toggle in status.Toggles)
            {
                LanAttackSurface.Add(LanAttackSurfaceToggleViewModel.From(toggle));
            }
        });
    }

    [RelayCommand]
    public async Task ToggleLanAttackSurfaceAsync(LanAttackSurfaceToggleViewModel? toggle)
    {
        if (toggle is null)
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Lan_ActionToggle", "Toggle LAN attack-surface control"), async () =>
        {
            var ack = await _client.Firewall.SetLanAttackSurfaceAsync(new LanAttackSurfaceRequest
            {
                Key = toggle.Key,
                Blocked = !toggle.Blocked,
            });
            StatusText = ack.Message;
            await LoadLanAttackSurfaceAsync();
        });
    }

    [RelayCommand]
    public async Task LoadServicesAsync()
    {
        await RunServiceActionAsync(I18n.T("Services_ActionLoad", "Load blockable services"), async () =>
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
        });
    }

    [RelayCommand]
    public async Task ToggleServiceAsync(BlockableServiceViewModel service)
    {
        if (!service.Blocked && service.Note.Length != 0 &&
            !_confirm.Confirm(I18n.T("Services_BlockTitle", "Block {0}", service.Name), service.Note))
        {
            return;
        }

        await RunServiceActionAsync(I18n.T("Services_ActionToggle", "Toggle blockable service"), async () =>
        {
            var ack = await _client.Policy.ToggleServiceAsync(new ServiceToggleRequest
            {
                Service = service.Name,
                Block = !service.Blocked,
            });
            StatusText = ack.Message;
            await LoadServicesAsync();
        });
    }

    // ─── Scheduled blocking ───────────────────────────────────────────────────

    [RelayCommand]
    public async Task LoadSchedulesAsync()
    {
        await RunServiceActionAsync(I18n.T("Schedules_ActionLoad", "Load schedules"), async () =>
        {
            var list = await _client.Policy.GetSchedulesAsync(new Empty());
            Schedules.Clear();
            foreach (var s in list.Schedules)
            {
                Schedules.Add(ScheduleRowViewModel.From(s));
            }

            StatusText = I18n.T("Schedules_Count", "{0} schedule(s)", Schedules.Count);
        });
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

        await RunServiceActionAsync(I18n.T("Schedules_ActionSave", "Save schedules"), async () =>
        {
            var ack = await _client.Policy.SetSchedulesAsync(list);
            StatusText = ack.Message;
            if (ack.Ok)
            {
                await LoadSchedulesAsync();
            }
        });
    }

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, s => StatusText = s, work);

    private static Task RunServiceActionAsync(string action, Action<string> setStatus, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, setStatus, work);
}

/// <summary>One subscribed IP-format blocklist row (NET-171).</summary>
public sealed class IpBlocklistRowViewModel
{
    public string Name { get; init; } = string.Empty;

    public string Url { get; init; } = string.Empty;

    public bool Enabled { get; init; }

    public long AddressCount { get; init; }

    public long RuleCount { get; init; }

    public string HealthText { get; init; } = string.Empty;

    public string LastRefreshText { get; init; } = string.Empty;

    public string ErrorText { get; init; } = string.Empty;

    public string EnabledText => Enabled
        ? I18n.T("Common_Enabled", "Enabled")
        : I18n.T("Common_Disabled", "Disabled");

    public static IpBlocklistRowViewModel From(IpBlocklistSource source) => new()
    {
        Name = source.Name,
        Url = source.Url,
        Enabled = source.Enabled,
        AddressCount = source.AddressCount,
        RuleCount = source.RuleCount,
        HealthText = (source.HealthStatus.Length != 0 ? source.HealthStatus : I18n.T("Common_NewLower", "new"))
                     + (source.Truncated ? $" · {I18n.T("IpBlock_TruncatedFlag", "truncated")}" : string.Empty),
        LastRefreshText = source.LastRefresh.Length != 0 ? TimeText.Compact(source.LastRefresh) : string.Empty,
        ErrorText = source.LastError,
    };
}

public sealed class SecureRuleConflictRowViewModel
{
    public string Name { get; init; } = string.Empty;

    public string DetectedText { get; init; } = string.Empty;

    public int RestoreAttempts { get; init; }

    public string LiveEvidence { get; init; } = string.Empty;

    public string TrackedEvidence { get; init; } = string.Empty;

    public string Summary => I18n.T(
        "SecureRules_ConflictSummary",
        "Quarantined after {0} restores · detected {1}",
        RestoreAttempts,
        DetectedText);

    public string Evidence => I18n.T(
        "SecureRules_ConflictEvidence",
        "Live: {0}{2}Tracked: {1}",
        LiveEvidence,
        TrackedEvidence,
        Environment.NewLine);

    public static SecureRuleConflictRowViewModel From(HostsGuard.Contracts.SecureRuleConflict conflict) => new()
    {
        Name = conflict.Name,
        DetectedText = TimeText.Compact(conflict.DetectedAt),
        RestoreAttempts = conflict.RestoreAttempts,
        LiveEvidence = conflict.LiveEvidence,
        TrackedEvidence = conflict.TrackedEvidence,
    };
}

public sealed partial class LanAttackSurfaceToggleViewModel : ObservableObject
{
    [ObservableProperty]
    private string _key = string.Empty;

    [ObservableProperty]
    private string _label = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ActionText))]
    [NotifyPropertyChangedFor(nameof(StateText))]
    private bool _blocked;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StateText))]
    private string _status = string.Empty;

    [ObservableProperty]
    private string _breakNote = string.Empty;

    public string ActionText => Blocked
        ? I18n.T("Common_Restore", "Restore")
        : I18n.T("Common_Block", "Block");

    public string StateText => Status;

    public static LanAttackSurfaceToggleViewModel From(LanAttackSurfaceToggle toggle) => new()
    {
        Key = toggle.Key,
        Label = toggle.Label,
        Blocked = toggle.Blocked,
        Status = toggle.Status,
        BreakNote = toggle.BreakNote,
    };
}

public sealed partial class PolicySubscriptionViewModel : ObservableObject
{
    [ObservableProperty]
    private long _id;

    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _url = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StateText))]
    private bool _enabled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ApplyModeText))]
    private bool _autoApply;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustText))]
    private string _pinHash = string.Empty;

    [ObservableProperty]
    private string _lastHash = string.Empty;

    [ObservableProperty]
    private long _lastCheckpointId;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastAppliedText))]
    private string _lastAppliedAt = string.Empty;

    [ObservableProperty]
    private string _lastError = string.Empty;

    [ObservableProperty]
    private string _lastErrorAt = string.Empty;

    public string StateText => Enabled
        ? I18n.T("PolicySub_StateEnabled", "Enabled")
        : I18n.T("PolicySub_StateDisabled", "Disabled");

    public string ApplyModeText => AutoApply
        ? I18n.T("PolicySub_ModeAutoApply", "Auto-apply")
        : I18n.T("PolicySub_ModeManualApproval", "Manual approval");

    public string TrustText => string.IsNullOrWhiteSpace(PinHash)
        ? I18n.T("PolicySub_TrustUnpinned", "Unpinned")
        : I18n.T("PolicySub_TrustPinned", "Pinned");

    public string LastAppliedText => string.IsNullOrWhiteSpace(LastAppliedAt)
        ? I18n.T("PolicySub_LastNever", "Never")
        : TimeText.Compact(LastAppliedAt);

    public string ErrorText => string.IsNullOrWhiteSpace(LastError) ? string.Empty : LastError;

    public static PolicySubscriptionViewModel From(PolicySubscription sub) => new()
    {
        Id = sub.Id,
        Name = sub.Name,
        Url = sub.Url,
        Enabled = sub.Enabled,
        AutoApply = sub.AutoApply,
        PinHash = sub.PinHash,
        LastHash = sub.LastHash,
        LastCheckpointId = sub.LastCheckpointId,
        LastAppliedAt = sub.LastAppliedAt,
        LastError = sub.LastError,
        LastErrorAt = sub.LastErrorAt,
    };
}
