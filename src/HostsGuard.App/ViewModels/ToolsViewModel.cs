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
        ("DHCP (default)", Array.Empty<string>()),
        ("Cloudflare (1.1.1.1)", new[] { "1.1.1.1", "1.0.0.1" }),
        ("Google (8.8.8.8)", new[] { "8.8.8.8", "8.8.4.4" }),
        ("Quad9 (9.9.9.9)", new[] { "9.9.9.9", "149.112.112.112" }),
    };

    private readonly HostsServiceClient _client;
    private readonly IConfirm _confirm;

    [ObservableProperty]
    private string _statusText = I18n.T("Status.Ready", "Ready");

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

    public ObservableCollection<DnsCacheEntryViewModel> DnsCacheEntries { get; } = new();

    public ObservableCollection<DnsAdapterRowViewModel> DnsAdapters { get; } = new();

    public ObservableCollection<PolicySubscriptionViewModel> PolicySubscriptions { get; } = new();

    public ObservableCollection<LanAttackSurfaceToggleViewModel> LanAttackSurface { get; } = new();

    public ObservableCollection<AppVpnBindingRowViewModel> AppVpnBindings { get; } = new();

    public static IReadOnlyList<string> ResolverNames { get; } = ResolverPresets.Select(p => p.Name).ToList();

    [RelayCommand]
    public async Task FlushDnsAsync()
    {
        await RunServiceActionAsync("Flush DNS cache", async () =>
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
    private string _dnsCacheStatusText = "Load DNS cache entries to verify what Windows is still resolving locally.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(FlushDnsCacheEntryCommand))]
    private DnsCacheEntryViewModel? _selectedDnsCacheEntry;

    [RelayCommand]
    public async Task LoadDnsCacheAsync()
    {
        await RunServiceActionAsync("Load DNS cache", s => DnsCacheStatusText = s, LoadDnsCacheCoreAsync);
    }

    [RelayCommand(CanExecute = nameof(CanFlushDnsCacheEntry))]
    public async Task FlushDnsCacheEntryAsync()
    {
        if (SelectedDnsCacheEntry is not { } row)
        {
            DnsCacheStatusText = "Select a cached DNS entry first.";
            return;
        }

        await RunServiceActionAsync("Flush DNS cache entry", s => DnsCacheStatusText = s, async () =>
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
            : $"{list.Message}; HTTPS/SVCB: {https} HTTPS, {svcb} SVCB. Windows cache does not expose ECH SVCB parameters.";
    }

    [RelayCommand]
    public async Task LoadLockStateAsync()
    {
        await RunServiceActionAsync("Load settings lock state", s => LockStatus = s, async () =>
        {
            var state = await _client.Policy.GetLockStateAsync(new Empty());
            LockEnabled = state.Enabled;
            LockStatus = state.Enabled
                ? state.Unlocked ? "Locked (temporarily unlocked)" : "Locked"
                : "Not locked";
        });
    }

    [RelayCommand]
    public async Task EnableLockAsync()
    {
        await RunServiceActionAsync("Enable settings lock", s => LockStatus = s, async () =>
        {
            var ack = await _client.Policy.SetLockAsync(new LockRequest { Action = "enable", Password = LockPassword });
            LockStatus = ack.Message;
            LockPassword = string.Empty;
            await LoadLockStateAsync();
        });
    }

    [RelayCommand]
    public async Task DisableLockAsync()
    {
        await RunServiceActionAsync("Disable settings lock", s => LockStatus = s, async () =>
        {
            var ack = await _client.Policy.SetLockAsync(new LockRequest { Action = "disable", Password = LockPassword });
            LockStatus = ack.Message;
            LockPassword = string.Empty;
            await LoadLockStateAsync();
        });
    }

    [RelayCommand]
    public async Task UnlockAsync()
    {
        await RunServiceActionAsync("Unlock settings", s => LockStatus = s, async () =>
        {
            var ack = await _client.Policy.UnlockAsync(new LockRequest { Password = LockPassword, Minutes = UnlockMinutes });
            LockStatus = ack.Message;
            LockPassword = string.Empty;
            await LoadLockStateAsync();
        });
    }

    [RelayCommand]
    public async Task ProtectHostsAsync()
    {
        await RunServiceActionAsync("Protect hosts file", async () =>
        {
            var ack = await _client.Policy.SetHostsProtectionAsync(new HostsProtectionRequest { Enabled = true });
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task ApplyResolverAsync()
    {
        await RunServiceActionAsync("Apply DNS resolver", async () =>
        {
            var preset = ResolverPresets.FirstOrDefault(p => p.Name == SelectedResolver);
            var request = new ResolverRequest();
            request.Servers.AddRange(preset.Servers ?? Array.Empty<string>());
            request.AdapterIds.AddRange(DnsAdapters.Where(adapter => adapter.IsSelected).Select(adapter => adapter.Id));
            if (request.AdapterIds.Count == 0)
            {
                StatusText = "Select at least one DNS adapter. VPN/tunnel adapters are never changed implicitly.";
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
        await RunServiceActionAsync("Load DNS adapters", LoadDnsAdaptersCoreAsync);
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
        await RunServiceActionAsync("Back up hosts file", async () =>
        {
            var ack = await _client.Hosts.BackupHostsAsync(new Empty());
            StatusText = ack.Ok ? $"Backup written: {ack.Message}" : ack.Message;
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
        await RunServiceActionAsync("Load hosts backups", async () =>
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
            StatusText = "Choose a backup before restoring.";
            return;
        }

        if (!_confirm.Confirm("Restore hosts backup",
            $"Replace the live hosts file with '{SelectedBackup.FileName}'? HostsGuard will write the selected backup immediately."))
        {
            return;
        }

        await RunServiceActionAsync("Restore hosts backup", async () =>
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
        await RunServiceActionAsync("Harden hosts ACL", async () =>
        {
            var ack = await _client.Hosts.HardenAclAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task ExportBundleAsync()
    {
        await RunServiceActionAsync("Export support bundle", async () =>
        {
            var ack = await _client.Diagnostics.ExportSupportBundleAsync(new SupportBundleRequest());
            StatusText = ack.Ok ? $"Support bundle: {ack.Message}" : ack.Message;
        });
    }

    [RelayCommand(CanExecute = nameof(CanInspect))]
    public async Task InspectAsync()
    {
        await RunServiceActionAsync("Inspect domain", s => InspectResult = s, async () =>
        {
            var result = await _client.Dns.InspectAsync(new DomainRequest { Domain = InspectDomain.Trim() });
            var records = result.Records.Count == 0
                ? "no records"
                : string.Join("; ", result.Records.Select(r => $"{r.Type} {r.Value}"));
            var ech = string.IsNullOrWhiteSpace(result.EchSummary)
                ? string.Empty
                : $" | ECH: {result.EchSummary} {result.EchRemediation}";
            InspectResult = $"{(result.Blocked ? "BLOCKED" : "reachable")} - {records} ({result.LatencyMs} ms){ech}";
        });
    }

    private bool CanInspect() => !string.IsNullOrWhiteSpace(InspectDomain);

    [ObservableProperty]
    private string _defenderStatusText = string.Empty;

    [RelayCommand]
    public async Task LoadDefenderStatusAsync()
    {
        await RunServiceActionAsync("Load Defender status", s => DefenderStatusText = s, async () =>
        {
            var status = await _client.Diagnostics.GetDefenderStatusAsync(new Empty());
            DefenderStatusText = !status.Available
                ? "Defender: not accessible"
                : status.HostsExcluded
                    ? "Defender: hosts file is excluded"
                    : status.PossibleRevert
                        ? "Defender: hosts file NOT excluded — blocks are missing (possible Defender revert)"
                        : "Defender: hosts file not excluded (HostsFileHijack detection may remove telemetry blocks)";
        });
    }

    [RelayCommand]
    public async Task AddDefenderExclusionAsync()
    {
        await RunServiceActionAsync("Add Defender exclusion", async () =>
        {
            var ack = await _client.Hosts.AddDefenderExclusionAsync(new Empty());
            StatusText = ack.Message;
            await LoadDefenderStatusAsync();
        });
    }

    [RelayCommand]
    public async Task RefreshThreatIntelAsync()
    {
        await RunServiceActionAsync("Refresh threat intelligence", async () =>
        {
            StatusText = "Refreshing threat intel...";
            var ack = await _client.Lists.RefreshThreatIntelAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task RefreshGeoIpAsync()
    {
        await RunServiceActionAsync("Refresh GeoIP database", async () =>
        {
            StatusText = "Downloading GeoIP database...";
            var ack = await _client.Lists.RefreshGeoIpAsync(new Empty());
            StatusText = ack.Message;
        });
    }

    [RelayCommand]
    public async Task EmergencyResetAsync()
    {
        if (!_confirm.Confirm("Emergency reset",
            "Reset the hosts file to Windows defaults? This removes every HostsGuard hosts-file block immediately."))
        {
            return;
        }

        await RunServiceActionAsync("Emergency reset hosts file", async () =>
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
    private string? _selectedProfile;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveProfileCommand))]
    private string _newProfileName = string.Empty;

    public ObservableCollection<string> Profiles { get; } = new();

    [RelayCommand]
    public async Task LoadProfilesAsync()
    {
        await RunServiceActionAsync("Load network profiles", async () =>
        {
            var list = await _client.Policy.ListProfilesAsync(new Empty());
            Profiles.Clear();
            foreach (var name in list.Names)
            {
                Profiles.Add(name);
            }

            ActiveProfile = list.Active.Length != 0 ? $"Active: {list.Active}" : "No active profile";
            SelectedProfile = list.Names.Contains(list.Active) ? list.Active : Profiles.FirstOrDefault();
        });
    }

    [RelayCommand(CanExecute = nameof(CanSaveProfile))]
    public async Task SaveProfileAsync()
    {
        await RunServiceActionAsync("Save network profile", async () =>
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

        await RunServiceActionAsync("Switch network profile", async () =>
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
            !_confirm.Confirm("Delete network profile",
                $"Delete network profile '{SelectedProfile}'? Saved firewall and hosts policy snapshots for this profile will be removed."))
        {
            return;
        }

        await RunServiceActionAsync("Delete network profile", async () =>
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
    private string _echPostureText = "Load encrypted DNS status to review HTTPS/SVCB and ECH visibility.";

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
        await RunServiceActionAsync("Load encrypted DNS status", s => DohStatusText = s, async () =>
        {
            var status = await _client.Dns.GetDohStatusAsync(new Empty());
            DohBlockingActive = status.BlockingActive;
            QuicBlockingActive = status.QuicBlocked;
            CnameCloakActive = status.CnameCloak;
            SniCaptureActive = status.SniCapture;
            DnsEncryptedOnly = status.DnsEncryptedOnly;
            DnrEnabled = status.DnrEnabled;
            var serviceBindings = $"{status.HttpsRecords} HTTPS / {status.SvcbRecords} SVCB cache rows";
            var dnrNote = status.DnrEnabled ? "; DNR on (network may auto-provision an encrypted resolver)" : string.Empty;
            DohStatusText = (status.Updated.Length != 0
                ? $"DoH intelligence: {status.ResolverIps} resolver IPs; {status.Source}; updated {status.Updated}; {serviceBindings}"
                : $"DoH intelligence: {status.ResolverIps} built-in resolver IPs; no refresh yet; {serviceBindings}") + dnrNote;
            EchPostureText = string.IsNullOrWhiteSpace(status.EchSummary)
                ? "ECH posture unavailable."
                : $"{status.EchSummary} {status.EchRemediation}";
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
        => !DnsEncryptedOnly || _confirm.Confirm("Encrypted-DNS-only system detected",
            "Your system is set to require encrypted DNS with no plaintext fallback. HostsGuard exempts your "
            + "current resolver, but blocking encrypted DNS could break name resolution if your DNS server changes. Continue?");

    [RelayCommand]
    public async Task ToggleSeeEverythingAsync()
    {
        if (!SeeEverythingActive && !ConfirmDohBlockArm())
        {
            return;
        }

        await RunServiceActionAsync("Toggle see-everything mode", async () =>
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
        });
    }

    [RelayCommand]
    public async Task ToggleQuicAsync()
    {
        await RunServiceActionAsync("Toggle QUIC blocking", async () =>
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
        await RunServiceActionAsync("Toggle CNAME cloak detection", async () =>
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
        await RunServiceActionAsync("Toggle SNI capture", async () =>
        {
            var ack = await _client.Dns.SetSniCaptureAsync(new SniCaptureRequest { Enabled = !SniCaptureActive });
            StatusText = ack.Message;
            await LoadDohStatusAsync();
        });
    }

    [RelayCommand]
    public async Task ApplyBaselineAsync()
    {
        await RunServiceActionAsync("Apply baseline rules", async () =>
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
        await RunServiceActionAsync("Load trusted publishers", async () =>
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
            !_confirm.Confirm("Remove trusted publisher",
                $"Stop auto-allowing software signed by \"{publisher}\"? Existing rules are unchanged."))
        {
            return;
        }

        await RunServiceActionAsync("Remove trusted publisher", async () =>
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
        await RunServiceActionAsync("Load trusted folders", async () =>
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
            !_confirm.Confirm("Remove trusted folder",
                $"Stop auto-allowing software in \"{folder}\"? Existing rules are unchanged."))
        {
            return;
        }

        await RunServiceActionAsync("Remove trusted folder", async () =>
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
        await RunServiceActionAsync("Load Secure Rules status", s => SecureRulesText = s, async () =>
        {
            var status = await _client.Firewall.GetSecureRulesAsync(new Empty());
            SecureRulesActive = status.Enabled;
            SecureRulesText = status.Enabled
                ? $"Secure Rules ON — {status.Tracked} HostsGuard rules protected"
                : "Secure Rules OFF — HostsGuard rules are not tamper-guarded";
        });
    }

    [RelayCommand]
    public async Task ToggleSecureRulesAsync()
    {
        await RunServiceActionAsync("Toggle Secure Rules", s => SecureRulesText = s, async () =>
        {
            var ack = await _client.Firewall.SetSecureRulesAsync(new SecureRulesRequest { Enabled = !SecureRulesActive });
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

        await RunServiceActionAsync("Toggle encrypted DNS blocking", s => DohStatusText = s, async () =>
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
        await RunServiceActionAsync("Refresh encrypted DNS intelligence", s => DohStatusText = s, async () =>
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
        await RunServiceActionAsync("Load LAN attack-surface controls", async () =>
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

        await RunServiceActionAsync("Toggle LAN attack-surface control", async () =>
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
        await RunServiceActionAsync("Load blockable services", async () =>
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
            !_confirm.Confirm($"Block {service.Name}", service.Note))
        {
            return;
        }

        await RunServiceActionAsync("Toggle blockable service", async () =>
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
        await RunServiceActionAsync("Load schedules", async () =>
        {
            var list = await _client.Policy.GetSchedulesAsync(new Empty());
            Schedules.Clear();
            foreach (var s in list.Schedules)
            {
                Schedules.Add(ScheduleRowViewModel.From(s));
            }

            StatusText = Plural.Of(Schedules.Count, "schedule");
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

        await RunServiceActionAsync("Save schedules", async () =>
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
        HealthText = (source.HealthStatus.Length != 0 ? source.HealthStatus : "new")
                     + (source.Truncated ? $" · {I18n.T("IpBlock_TruncatedFlag", "truncated")}" : string.Empty),
        LastRefreshText = source.LastRefresh.Length != 0 ? TimeText.Compact(source.LastRefresh) : string.Empty,
        ErrorText = source.LastError,
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
