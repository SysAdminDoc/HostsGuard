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
            var ack = await _client.Dns.SetResolverAsync(request);
            StatusText = ack.Message;
        });
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
            var ack = await _client.Diagnostics.ExportSupportBundleAsync(new Empty());
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
            InspectResult = $"{(result.Blocked ? "BLOCKED" : "reachable")} — {records} ({result.LatencyMs} ms)";
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
            DohStatusText = status.Updated.Length != 0
                ? $"DoH intelligence: {status.ResolverIps} resolver IPs; {status.Source}; updated {status.Updated}"
                : $"DoH intelligence: {status.ResolverIps} built-in resolver IPs; no refresh yet";
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

    // ─── VPN-presence kill-switch (NET-119) ──────────────────────────────────

    public ObservableCollection<AdapterRowViewModel> Adapters { get; } = new();

    [ObservableProperty]
    private AdapterRowViewModel? _selectedAdapter;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveAppVpnBindingCommand))]
    private AdapterRowViewModel? _selectedAppVpnAdapter;

    [ObservableProperty]
    private bool _killSwitchEnabled;

    [ObservableProperty]
    private string _killSwitchStatusText = "VPN kill-switch off.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveAppVpnBindingCommand))]
    private string _appVpnProgramPath = string.Empty;

    [ObservableProperty]
    private string _appVpnStatusText = "No app VPN bindings.";

    [RelayCommand]
    public async Task LoadKillSwitchAsync()
    {
        await RunServiceActionAsync("Load VPN kill-switch", s => KillSwitchStatusText = s, async () =>
        {
            var status = await _client.Firewall.GetKillSwitchAsync(new Empty());
            ReplaceAdapters(status.Adapters);

            KillSwitchEnabled = status.Enabled;
            SelectedAdapter = Adapters.FirstOrDefault(a => a.Match == status.Adapter)
                ?? Adapters.FirstOrDefault(a => a.Label.Contains(", VPN", StringComparison.Ordinal))
                ?? Adapters.FirstOrDefault();
            KillSwitchStatusText = status.Enabled
                ? status.Engaged
                    ? $"ENGAGED — all outbound blocked while '{status.Adapter}' is down"
                    : $"On — watching '{status.Adapter}'"
                : "VPN kill-switch off.";
        });
    }

    [RelayCommand]
    public async Task ToggleKillSwitchAsync()
    {
        var adapter = SelectedAdapter?.Match ?? string.Empty;
        if (!KillSwitchEnabled)
        {
            if (adapter.Length == 0)
            {
                StatusText = "Choose a VPN adapter before enabling the kill-switch.";
                return;
            }

            if (!_confirm.Confirm("Enable VPN kill-switch",
                $"Block ALL outbound traffic whenever '{adapter}' is down? Existing allow rules still apply — "
                + "keep one for your VPN client so the tunnel can reconnect. You can turn this off here at any time."))
            {
                return;
            }
        }

        await RunServiceActionAsync("Toggle VPN kill-switch", s => KillSwitchStatusText = s, async () =>
        {
            var ack = await _client.Firewall.SetKillSwitchAsync(new KillSwitchRequest
            {
                Enabled = !KillSwitchEnabled,
                Adapter = adapter,
            });
            StatusText = ack.Message;
            await LoadKillSwitchAsync();
        });
    }

    [RelayCommand]
    public async Task LoadAppVpnBindingsAsync()
    {
        await RunServiceActionAsync("Load app VPN bindings", s => AppVpnStatusText = s, async () =>
        {
            var status = await _client.Firewall.GetAppVpnBindingsAsync(new Empty());
            ReplaceAdapters(status.Adapters);
            AppVpnBindings.Clear();
            foreach (var binding in status.Bindings.OrderBy(b => b.ProgramPath, StringComparer.OrdinalIgnoreCase))
            {
                AppVpnBindings.Add(AppVpnBindingRowViewModel.From(binding));
            }

            SelectedAppVpnAdapter ??= Adapters.FirstOrDefault(a => a.Label.Contains(", VPN", StringComparison.Ordinal))
                ?? Adapters.FirstOrDefault();
            AppVpnStatusText = AppVpnBindings.Count == 0
                ? "No app VPN bindings."
                : $"{Plural.Of(AppVpnBindings.Count, "app VPN binding")}";
        });
    }

    [RelayCommand(CanExecute = nameof(CanSaveAppVpnBinding))]
    public async Task SaveAppVpnBindingAsync()
    {
        var program = AppVpnProgramPath.Trim();
        var adapter = SelectedAppVpnAdapter?.Match ?? string.Empty;
        await RunServiceActionAsync("Save app VPN binding", s => AppVpnStatusText = s, async () =>
        {
            var ack = await _client.Firewall.SetAppVpnBindingAsync(new AppVpnBindingRequest
            {
                ProgramPath = program,
                Adapter = adapter,
                Enabled = true,
            });
            StatusText = ack.Message;
            AppVpnStatusText = ack.Message;
            if (ack.Ok)
            {
                AppVpnProgramPath = string.Empty;
                await LoadAppVpnBindingsAsync();
            }
        });
    }

    private bool CanSaveAppVpnBinding()
        => !string.IsNullOrWhiteSpace(AppVpnProgramPath) && SelectedAppVpnAdapter is not null;

    [RelayCommand]
    public async Task RemoveAppVpnBindingAsync(AppVpnBindingRowViewModel? binding)
    {
        if (binding is null || string.IsNullOrWhiteSpace(binding.ProgramPath))
        {
            return;
        }

        await RunServiceActionAsync("Remove app VPN binding", s => AppVpnStatusText = s, async () =>
        {
            var ack = await _client.Firewall.SetAppVpnBindingAsync(new AppVpnBindingRequest
            {
                ProgramPath = binding.ProgramPath,
                Adapter = binding.Adapter,
                Enabled = false,
            });
            StatusText = ack.Message;
            AppVpnStatusText = ack.Message;
            await LoadAppVpnBindingsAsync();
        });
    }

    private void ReplaceAdapters(IEnumerable<NetworkAdapterInfo> adapters)
    {
        var killMatch = SelectedAdapter?.Match ?? string.Empty;
        var appMatch = SelectedAppVpnAdapter?.Match ?? string.Empty;
        Adapters.Clear();
        foreach (var a in adapters)
        {
            Adapters.Add(new AdapterRowViewModel
            {
                Match = a.Name,
                Label = $"{a.Name} — {a.Description} ({(a.IsUp ? "up" : "down")}{(a.IsVpnLikely ? ", VPN" : string.Empty)})",
            });
        }

        if (killMatch.Length != 0)
        {
            SelectedAdapter = Adapters.FirstOrDefault(a => a.Match == killMatch);
        }

        if (appMatch.Length != 0)
        {
            SelectedAppVpnAdapter = Adapters.FirstOrDefault(a => a.Match == appMatch);
        }
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
        await RunServiceActionAsync("Load AI status", s => AiStatusText = s, async () =>
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
        });
    }

    [RelayCommand]
    public async Task SaveAiConfigAsync()
    {
        await RunServiceActionAsync("Save AI configuration", s => AiStatusText = s, async () =>
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
        });
    }

    [RelayCommand]
    public async Task CategorizeAllAsync()
    {
        await RunServiceActionAsync("Categorize domains with AI", s => AiStatusText = s, async () =>
        {
            AiStatusText = "Asking DeepSeek to categorize uncategorized blocked domains...";
            var result = await _client.Hosts.CategorizeDomainsAsync(
                new CategorizeRequest { AllUncategorized = true });
            StatusText = result.Message;
            await LoadAiStatusAsync();
        });
    }

    /// <summary>
    /// Save everything the AI has learned (purposes, categories, connection
    /// info) to a user-readable JSON file — the review path for promoting
    /// entries into the app's curated built-ins.
    /// </summary>
    [RelayCommand]
    public async Task ExportAiKnowledgeAsync()
    {
        await RunServiceActionAsync("Export AI knowledge", s => AiStatusText = s, async () =>
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
        });
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
        await RunServiceActionAsync("Load AI knowledge", s => KnowledgeStatusText = s, async () =>
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
        });
    }

    [RelayCommand]
    public async Task PromoteKnowledgeAsync(KnowledgeEntryViewModel row)
    {
        if (row is null)
        {
            return;
        }

        await RunServiceActionAsync("Promote AI knowledge", s => KnowledgeStatusText = s, async () =>
        {
            var request = new KnowledgeReviewRequest();
            request.Actions.Add(new KnowledgeReviewAction { Kind = row.Kind, Key = row.Key, Action = "promote", Value = row.EditValue });
            var ack = await _client.Hosts.PromoteKnowledgeAsync(request);
            StatusText = ack.Message;
            await LoadKnowledgeAsync();
        });
    }

    [RelayCommand]
    public async Task DiscardKnowledgeAsync(KnowledgeEntryViewModel row)
    {
        if (row is null)
        {
            return;
        }

        await RunServiceActionAsync("Discard AI knowledge", s => KnowledgeStatusText = s, async () =>
        {
            var request = new KnowledgeReviewRequest();
            request.Actions.Add(new KnowledgeReviewAction { Kind = row.Kind, Key = row.Key, Action = "discard" });
            var ack = await _client.Hosts.PromoteKnowledgeAsync(request);
            StatusText = ack.Message;
            await LoadKnowledgeAsync();
        });
    }

    [RelayCommand]
    public async Task MarkKnowledgeReviewedAsync()
    {
        await RunServiceActionAsync("Mark AI knowledge reviewed", s => KnowledgeStatusText = s, async () =>
        {
            var ack = await _client.Hosts.PromoteKnowledgeAsync(new KnowledgeReviewRequest { MarkReviewed = true });
            StatusText = ack.Message;
            await LoadKnowledgeAsync();
        });
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

        await RunServiceActionAsync("Correct domain knowledge", s => KnowledgeStatusText = s, async () =>
        {
            var ack = await _client.Hosts.OverrideKnowledgeAsync(new KnowledgeOverrideRequest
            {
                Kind = CorrectKind,
                Key = domain,
                Value = CorrectValue.Trim(),
            });
            StatusText = ack.Message;
            CorrectValue = string.Empty;
            await LoadKnowledgeAsync();
        });
    }

    // ─── Blocklist intelligence ───────────────────────────────────────────────

    [ObservableProperty]
    private string _intelStatusText = "Checking blocklist intelligence…";

    public async Task LoadIntelStatusAsync()
    {
        await RunServiceActionAsync("Load blocklist intelligence", s => IntelStatusText = s, async () =>
        {
            var status = await _client.Lists.GetBlocklistIntelligenceAsync(new Empty());
            IntelStatusText = status.Refreshing
                ? "Downloading reference blocklists in the background…"
                : status.Lists == 0
                    ? "No reference lists downloaded yet — refresh to build the block-candidate index."
                    : $"{Plural.Of(status.Lists, "reference list")} · {status.Domains:N0} domains indexed"
                      + (status.Refreshed.Length != 0 ? $" · refreshed {TimeText.Compact(status.Refreshed)}" : string.Empty);
        });
    }

    [RelayCommand]
    public async Task RefreshIntelAsync()
    {
        await RunServiceActionAsync("Refresh blocklist intelligence", s => IntelStatusText = s, async () =>
        {
            IntelStatusText = "Downloading reference blocklists — this can take a few minutes…";
            var ack = await _client.Lists.RefreshBlocklistIntelligenceAsync(new Empty());
            StatusText = ack.Message;
            await LoadIntelStatusAsync();
        });
    }

    private Task RunServiceActionAsync(string action, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, s => StatusText = s, work);

    private static Task RunServiceActionAsync(string action, Action<string> setStatus, Func<Task> work) =>
        ServiceActionGuard.RunAsync(action, setStatus, work);
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

    public string ActionText => Blocked ? "Restore" : "Block";

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
