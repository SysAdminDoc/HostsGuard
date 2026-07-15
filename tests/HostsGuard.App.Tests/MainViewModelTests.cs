using System.IO;
using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Service;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>
/// Shell ViewModel against a live in-process service: connect populates the
/// status bar and the Hosts tab; theme/scale changes persist through the
/// shared config file without touching Python-owned keys.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MainViewModelTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private ShellFirewallEngine _fw = null!;
    private ShellFlowTerminator _flows = null!;
    private KillSwitchMonitor _killSwitch = null!;
    private HostsServiceClient _client = null!;
    private AppConfigStore _config = null!;
    private string _token = null!;
    private string _pipe = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_mainvm_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _fw = new ShellFirewallEngine();
        _flows = new ShellFlowTerminator();
        _state = new ServiceState(
            new HostsEngine(hostsPath),
            new HostsDatabase(Path.Combine(_dir, "db.sqlite")),
            _fw,
            new FirewallIdentity(Path.Combine(_dir, "fw_identities.json")),
            dataDir: _dir,
            listFetcher: new EmptyListFetcher(),
            flowTerminator: _flows,
            connectionSnapshot: () => Array.Empty<ConnectionInfo>());
        _killSwitch = new KillSwitchMonitor(_fw, _state.Db, _ => false, _dir);
        _state.KillSwitch = _killSwitch;
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.MainVmTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
        _client = CreateClient();
        _config = new AppConfigStore(Path.Combine(_dir, "config.json"));
        _config.Load();
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
        _killSwitch.Dispose();
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private HostsServiceClient CreateClient() => new(NamedPipeChannel.Create(_token, _pipe));

    private MainViewModel CreateShell() => new(CreateClient, _config, new ThemeManager(), new FakeConfirm(true));

    [Fact]
    public async Task SendDecision_reports_whether_the_service_applied_it()
    {
        using var vm = CreateShell();

        // Not connected yet — delivery must report failure, not silently drop.
        (await vm.SendDecisionAsync(new Contracts.ConnectionDecision
        {
            Application = @"C:\apps\a.exe",
            Verdict = "allow",
        })).Should().BeFalse();

        await vm.ConnectCommand.ExecuteAsync(null);

        // Service rejects an invalid verdict → delivered-but-not-applied is false.
        (await vm.SendDecisionAsync(new Contracts.ConnectionDecision
        {
            Application = @"C:\apps\a.exe",
            Verdict = "maybe",
        })).Should().BeFalse();

        // A valid decision lands and is applied.
        (await vm.SendDecisionAsync(new Contracts.ConnectionDecision
        {
            Application = @"C:\apps\a.exe",
            Verdict = "allow",
            Duration = "always",
        })).Should().BeTrue();
    }

    [Fact]
    public async Task Connect_populates_status_and_hosts_tab()
    {
        await _client.Hosts.BlockAsync(new Contracts.DomainRequest { Domain = "ads.example.com", Source = "manual" });

        using var vm = CreateShell();
        await vm.ConnectCommand.ExecuteAsync(null);

        vm.IsConnected.Should().BeTrue();
        vm.ConnectionText.Should().Contain("Connected");
        vm.ServiceVersion.Should().NotBeNullOrEmpty();
        vm.HostsBlocked.Should().Be(1);
        vm.Hosts.Should().NotBeNull();
        vm.Hosts!.Domains.Should().BeEmpty("the inactive Hosts File tab hydrates only on first activation");

        await vm.LoadTabAsync(2);

        vm.Hosts!.Domains.Should().ContainSingle(d => d.Domain == "ads.example.com");
        vm.FilteringModeTitle.Should().Be("Normal");
        vm.EnforcementPauseTitle.Should().Be("Active");
        vm.SetFilteringModeCommand.CanExecute("notify").Should().BeTrue();
        vm.SetGlobalModeCommand.CanExecute("block-all").Should().BeTrue();
        vm.PauseEnforcementCommand.CanExecute("5").Should().BeTrue();
        vm.RestoreSafeNetworkPostureCommand.CanExecute(null).Should().BeTrue();
    }

    [Fact]
    public async Task Connect_hydrates_only_the_active_tab_and_caches_first_activation()
    {
        using var vm = CreateShell();
        var loadedTabs = new List<int>();
        vm.HydrationPlanOverride = tabIndex =>
        [
            new ShellHydrationWork($"tab-{tabIndex}", _ =>
            {
                loadedTabs.Add(tabIndex);
                return Task.CompletedTask;
            }),
        ];

        await vm.ConnectAsync();

        loadedTabs.Should().Equal(0);

        await vm.LoadTabAsync(5);
        await vm.LoadTabAsync(5);

        loadedTabs.Should().Equal(0, 5);
    }

    [Fact]
    public async Task Optional_tab_failure_keeps_the_connected_shell_available()
    {
        using var vm = CreateShell();
        vm.HydrationPlanOverride = _ =>
        [
            new ShellHydrationWork(
                "optional",
                _ => Task.FromException(new InvalidOperationException("optional surface failed"))),
        ];

        await vm.ConnectAsync();

        vm.IsConnected.Should().BeTrue();
        vm.ConnectionText.Should().Contain("need attention");
        vm.Activity.Should().NotBeNull();
        vm.Activity!.StatusText.Should().Contain("Use Refresh to retry")
            .And.Contain("optional surface failed");
    }

    [Fact]
    public async Task Reconnect_cancels_stale_hydration_without_clearing_the_new_session()
    {
        using var vm = CreateShell();
        var firstStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var planCount = 0;
        vm.HydrationPlanOverride = _ =>
        [
            new ShellHydrationWork("active-tab", async cancellationToken =>
            {
                if (Interlocked.Increment(ref planCount) == 1)
                {
                    firstStarted.SetResult();
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                }
            }),
        ];

        var staleConnect = vm.ConnectAsync();
        await firstStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var currentConnect = vm.ConnectAsync();
        await Task.WhenAll(staleConnect, currentConnect);

        planCount.Should().Be(2);
        vm.IsConnected.Should().BeTrue();
        vm.ConnectionText.Should().Contain("Connected").And.NotContain("unavailable");
        vm.Activity.Should().NotBeNull();
        vm.FwActivity.Should().NotBeNull();
    }

    [Fact]
    public async Task Tray_profile_path_loads_switches_and_reflects_external_changes()
    {
        await _client.Policy.SaveProfileAsync(new Contracts.ProfileRequest { Name = "Home" });
        await _client.Policy.SaveProfileAsync(new Contracts.ProfileRequest { Name = "Work" });
        await _client.Policy.SwitchProfileAsync(new Contracts.ProfileRequest { Name = "Work" });
        using var vm = CreateShell();
        await vm.ConnectAsync();
        var tools = vm.Tools!;
        tools.Should().NotBeNull();

        (await tools.LoadProfilesForTrayAsync()).Should().BeTrue();
        tools.Profiles.Should().Contain(new[] { "Home", "Work" });
        tools.ActiveProfileName.Should().Be("Work");

        await _client.Policy.SwitchProfileAsync(new Contracts.ProfileRequest { Name = "Home" });
        (await tools.LoadProfilesForTrayAsync()).Should().BeTrue();
        tools.ActiveProfileName.Should().Be("Home", "opening the tray must reflect an external switch");

        (await tools.SwitchToProfileAsync("Work")).Should().BeTrue();
        tools.ActiveProfileName.Should().Be("Work");
        (await _client.Policy.ListProfilesAsync(new Contracts.Empty())).Active.Should().Be("Work");
    }

    [Fact]
    public async Task Tray_profile_path_reports_settings_lock_rejection_without_losing_profiles()
    {
        await _client.Policy.SaveProfileAsync(new Contracts.ProfileRequest { Name = "Work" });
        (await _client.Policy.SetLockAsync(new Contracts.LockRequest
        {
            Action = "enable",
            Password = "correct-horse-battery-staple",
        })).Ok.Should().BeTrue();
        using var vm = CreateShell();
        await vm.ConnectAsync();
        var tools = vm.Tools!;
        tools.Should().NotBeNull();

        (await tools.LoadProfilesForTrayAsync()).Should().BeTrue();
        (await tools.SwitchToProfileAsync("Work")).Should().BeFalse();

        tools.StatusText.Should().ContainEquivalentOf("locked");
        tools.Profiles.Should().Contain("Work");
        tools.ActiveProfileName.Should().BeEmpty();
    }

    [Fact]
    public async Task Active_remote_session_warning_can_cancel_global_lockdown()
    {
        var checkedAt = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        _state.RemoteSessions = new FixedRemoteSessions(new RemoteSessionSnapshot(
            true,
            string.Empty,
            checkedAt,
            [new RemoteDesktopSession(
                8,
                "active",
                true,
                "OPS-LAPTOP",
                "203.0.113.18",
                checkedAt.AddMinutes(-20),
                null)]));
        var confirm = new FakeConfirm(false);
        using var vm = new MainViewModel(CreateClient, _config, new ThemeManager(), confirm);
        await vm.ConnectCommand.ExecuteAsync(null);

        await vm.SetGlobalModeAsync("block-all");

        _fw.OutboundBlock.Should().BeFalse();
        confirm.Prompts.Should().ContainSingle().Which.Should()
            .Contain("Remote Desktop")
            .And.Contain("session 8 from 203.0.113.18");
    }

    [Fact]
    public void Disconnected_status_rail_is_explicit_and_service_commands_are_disabled()
    {
        using var vm = CreateShell();

        vm.ConnectionStateTitle.Should().Be("Disconnected");
        vm.FilteringModeTitle.Should().Be("Unavailable");
        vm.FilteringModeDisplayText.Should().Be("Connect to view or change filtering mode.");
        vm.EnforcementPauseTitle.Should().Be("Unavailable");
        vm.EnforcementPauseDisplayText.Should().Be("Connect to view or change global posture.");
        vm.HostsBlockedText.Should().Be("Hosts file: unavailable");
        vm.DbBlockedText.Should().Be("Blocked: unavailable");
        vm.DbAllowedText.Should().Be("Allowed: unavailable");
        vm.ServiceVersionText.Should().Be("service unavailable");
        vm.ServiceCommandAvailabilityText.Should().Contain("Reconnect first");
        vm.SetFilteringModeCommand.CanExecute("notify").Should().BeFalse();
        vm.SetGlobalModeCommand.CanExecute("block-all").Should().BeFalse();
        vm.PauseEnforcementCommand.CanExecute("5").Should().BeFalse();
        vm.RestoreSafeNetworkPostureCommand.CanExecute(null).Should().BeFalse();
    }

    [Fact]
    public async Task Failed_connect_reports_unavailable_instead_of_crashing()
    {
        using var vm = new MainViewModel(
            () => throw new IOException("pipe not found"), _config, new ThemeManager(), new FakeConfirm(true));

        await vm.ConnectCommand.ExecuteAsync(null);

        vm.IsConnected.Should().BeFalse();
        vm.ConnectionText.Should().Contain("Service unavailable");
    }

    [Fact]
    public async Task Safe_posture_command_reports_unavailable_when_service_is_disconnected()
    {
        using var vm = CreateShell();

        vm.RestoreSafeNetworkPostureCommand.CanExecute(null).Should().BeFalse();
        await vm.RestoreSafeNetworkPostureAsync();

        vm.ConnectionText.Should().Be("Safe posture unavailable - service is not connected");
    }

    [Fact]
    public async Task Safe_posture_command_restores_nonblocking_posture_without_touching_hosts_blocks()
    {
        await _client.Hosts.BlockAsync(new Contracts.DomainRequest { Domain = "ads.example.com", Source = "manual" });
        await _client.Consent.SetModeAsync(new Contracts.FilteringMode { Mode = "notify" });
        await _client.Firewall.SetGlobalModeAsync(new Contracts.GlobalModeRequest { Mode = "block-all" });
        await _client.Firewall.BlockEncryptedDnsAsync(new Contracts.DohBlockRequest());
        await _client.Firewall.BlockQuicAsync(new Contracts.Empty());
        await _client.Dns.SetCnameCloakAsync(new Contracts.CnameCloakRequest { Enabled = true });
        await _client.Firewall.SetFlowTeardownAsync(new Contracts.FlowTeardownRequest { Enabled = true });
        await _client.Firewall.SetKillSwitchAsync(new Contracts.KillSwitchRequest
        {
            Enabled = true,
            Adapter = "Test VPN",
        });
        _fw.OutboundBlock.Should().BeTrue();

        using var vm = CreateShell();
        await vm.ConnectCommand.ExecuteAsync(null);

        await vm.RestoreSafeNetworkPostureCommand.ExecuteAsync(null);

        var mode = await _client.Consent.GetModeAsync(new Contracts.Empty());
        var posture = await _client.Firewall.GetPostureAsync(new Contracts.Empty());
        var doh = await _client.Dns.GetDohStatusAsync(new Contracts.Empty());
        var flow = await _client.Firewall.GetFlowTeardownAsync(new Contracts.Empty());
        var killSwitch = await _client.Firewall.GetKillSwitchAsync(new Contracts.Empty());
        var status = await _client.Diagnostics.GetStatusAsync(new Contracts.Empty());

        mode.Mode.Should().Be("normal");
        posture.Lockdown.Should().BeFalse();
        posture.Profiles.Should().OnlyContain(p => !p.OutboundBlock);
        doh.BlockingActive.Should().BeFalse();
        doh.QuicBlocked.Should().BeFalse();
        doh.CnameCloak.Should().BeFalse();
        flow.Enabled.Should().BeFalse();
        killSwitch.Enabled.Should().BeFalse();
        killSwitch.Engaged.Should().BeFalse();
        status.HostsBlocked.Should().Be(1);
        vm.ConnectionText.Should().StartWith("Safe network posture restored - hosts-file blocks left unchanged.");
    }

    [Fact]
    public async Task Reconnect_recreates_client_after_token_rotation_and_restores_live_feeds()
    {
        using var vm = CreateShell();
        vm.SetGlobalModeCommand.CanExecute("block-all").Should().BeFalse();
        await vm.ConnectCommand.ExecuteAsync(null);
        vm.IsConnected.Should().BeTrue();
        vm.SetGlobalModeCommand.CanExecute("block-all").Should().BeTrue();
        var firstActivity = vm.Activity;
        var firstFwActivity = vm.FwActivity;

        await RotateServiceTokenAsync();
        await vm.ConnectCommand.ExecuteAsync(null);

        vm.IsConnected.Should().BeTrue();
        vm.SetGlobalModeCommand.CanExecute("block-all").Should().BeTrue();
        vm.Activity.Should().NotBeNull().And.NotBeSameAs(firstActivity);
        vm.FwActivity.Should().NotBeNull().And.NotBeSameAs(firstFwActivity);

        await PublishDnsUntilVisibleAsync(vm, "after-restart.example.com");
        await PublishConnectionUntilVisibleAsync(vm, "198.51.100.44", 443);
    }

    [Fact]
    public void Theme_toggle_flips_and_persists()
    {
        using var vm = CreateShell();
        vm.Theme.Should().Be("dark");

        vm.ToggleThemeCommand.Execute(null);

        vm.Theme.Should().Be("light");
        var reread = new AppConfigStore(_config.FilePath);
        reread.Load();
        reread.Theme.Should().Be("light");
    }

    [Fact]
    public void Scale_change_updates_transform_factor_and_persists()
    {
        using var vm = CreateShell();

        vm.UiScalePct = 125;

        vm.UiScale.Should().Be(1.25);
        var reread = new AppConfigStore(_config.FilePath);
        reread.Load();
        reread.UiScalePct.Should().Be(125);
    }

    [Fact]
    public async Task Check_for_updates_reports_latest_release_without_opening_a_browser()
    {
        var checker = new FakeReleaseUpdateChecker(
            new ReleaseUpdateResult(
                ReleaseUpdateState.UpdateAvailable,
                "0.12.15",
                "v0.12.16",
                new DateTimeOffset(2026, 7, 7, 12, 0, 0, TimeSpan.Zero),
                [new ReleaseAssetInfo("HostsGuard-v0.12.16-dotnet-Setup.exe", 10, "sha256:abc", null)],
                "Update available: v0.12.16 (published 2026-07-07). HostsGuard-v0.12.16-dotnet-Setup.exe (10 B, sha256:abc; 1 asset listed). No auto-install performed."));
        using var vm = new MainViewModel(
            CreateClient, _config, new ThemeManager(), new FakeConfirm(true), releaseUpdateChecker: checker);

        await vm.CheckForUpdatesCommand.ExecuteAsync(null);

        checker.InstalledVersion.Should().Be(vm.AppVersion);
        vm.ConnectionText.Should().Contain("Update available")
            .And.Contain("v0.12.16")
            .And.Contain("sha256:abc")
            .And.Contain("No auto-install");
    }

    [Fact]
    public async Task Ai_key_affordance_reflects_write_only_service_status()
    {
        using var vm = CreateShell();
        await vm.ConnectCommand.ExecuteAsync(null);
        vm.Tools.Should().NotBeNull();
        var tools = vm.Tools!;

        await tools.LoadAiStatusAsync();
        tools.AiKeyStorageText.Should().Be(
            "No API key stored — enter one before enabling AI categorization.");

        _state.Ai.SaveSettings("sk-secret", "deepseek-chat", string.Empty, enabled: true);
        await tools.LoadAiStatusAsync();

        tools.AiKeyStorageText.Should().Be(
            "API key stored — leave the field blank to keep it, or enter a new key to replace it.");
        tools.AiStatusText.Should().StartWith("DeepSeek key stored");
        tools.AiApiKey.Should().BeEmpty("the service never returns the write-only secret");
    }

    [Fact]
    public async Task Local_blocklist_preview_is_non_mutating_and_confirmed_import_uses_previewed_bytes()
    {
        var path = Path.Combine(_dir, "my-local.hosts");
        await File.WriteAllTextAsync(path, string.Join('\n',
            "0.0.0.0 ads.local.example",
            "tracker.local.example",
            "not a domain !!!"));
        var picker = new FakePicker { OpenPath = path };

        var declined = new BlocklistsViewModel(_client, new FakeConfirm(false), picker);
        await declined.PreviewLocalFileCommand.ExecuteAsync(null);

        declined.HasLocalPreview.Should().BeTrue();
        declined.LocalPreviewTotal.Should().Be(2);
        declined.LocalPreviewAdded.Should().Be(2);
        declined.LocalPreviewInvalid.Should().Be(1);
        declined.LocalPreviewSummary.Should().Contain("2 parsed").And.Contain("2 new").And.Contain("1 invalid");
        _state.Hosts.GetBlocked().Should().NotContain(new[] { "ads.local.example", "tracker.local.example" });

        await declined.ImportLocalPreviewCommand.ExecuteAsync(null);
        _state.Hosts.GetBlocked().Should().NotContain("ads.local.example", "declining confirmation cannot mutate");

        var accepted = new BlocklistsViewModel(_client, new FakeConfirm(true), picker);
        await accepted.PreviewLocalFileCommand.ExecuteAsync(null);
        await File.WriteAllTextAsync(path, "0.0.0.0 changed-after-preview.example\n");
        await accepted.ImportLocalPreviewCommand.ExecuteAsync(null);

        _state.Hosts.GetBlocked().Should().Contain(new[] { "ads.local.example", "tracker.local.example" })
            .And.NotContain("changed-after-preview.example", "import applies the exact previewed bytes");
        accepted.Sources.Should().ContainSingle(source =>
            source.Name == "my-local" && source.Url == "local:my-local" && source.Subscribed);
        accepted.HasLocalPreview.Should().BeFalse();
    }

    [Fact]
    public async Task Local_blocklist_picker_reports_encoding_size_and_cancel_without_mutation()
    {
        var picker = new FakePicker();
        var vm = new BlocklistsViewModel(_client, new FakeConfirm(true), picker);

        await vm.PreviewLocalFileCommand.ExecuteAsync(null);
        vm.HasLocalPreview.Should().BeFalse();
        _state.Hosts.GetBlocked().Should().BeEmpty();

        var invalidPath = Path.Combine(_dir, "invalid-utf8.list");
        await File.WriteAllBytesAsync(invalidPath, [0xC3, 0x28]);
        picker.OpenPath = invalidPath;
        await vm.PreviewLocalFileCommand.ExecuteAsync(null);
        vm.HasLocalPreview.Should().BeFalse();
        vm.LocalPreviewSummary.Should().Contain("not valid UTF-8");

        var hugePath = Path.Combine(_dir, "too-large.list");
        await using (var huge = new FileStream(hugePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            huge.SetLength(BlocklistCatalog.MaxBlocklistBytes + 1L);
        }

        picker.OpenPath = hugePath;
        await vm.PreviewLocalFileCommand.ExecuteAsync(null);
        vm.HasLocalPreview.Should().BeFalse();
        vm.LocalPreviewSummary.Should().Contain("exceeds the 25 MB");
        _state.Hosts.GetBlocked().Should().BeEmpty();
    }

    private sealed class FakeReleaseUpdateChecker(ReleaseUpdateResult result) : IReleaseUpdateChecker
    {
        public string? InstalledVersion { get; private set; }

        public Task<ReleaseUpdateResult> CheckAsync(
            string installedVersion, CancellationToken cancellationToken = default)
        {
            InstalledVersion = installedVersion;
            return Task.FromResult(result);
        }
    }

    private sealed class FixedRemoteSessions(RemoteSessionSnapshot snapshot) : IRemoteSessionSource
    {
        public RemoteSessionSnapshot Snapshot() => snapshot;
    }

    private async Task RotateServiceTokenAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
        _token = SessionToken.Generate();
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
        _client = CreateClient();
    }

    private async Task PublishDnsUntilVisibleAsync(MainViewModel vm, string domain)
    {
        for (var i = 0; i < 40; i++)
        {
            _state.RecordDns(domain, "edge.exe", 1234);
            if (vm.Activity?.Rows.Any(r => r.Domain == domain) == true)
            {
                return;
            }

            await Task.Delay(50);
        }

        vm.Activity.Should().NotBeNull();
        vm.Activity!.Rows.Select(r => r.Domain).Should().Contain(domain);
    }

    private async Task PublishConnectionUntilVisibleAsync(MainViewModel vm, string remoteAddr, int remotePort)
    {
        for (var i = 0; i < 40; i++)
        {
            _state.PublishConnection(new ConnectionInfo(
                "TCP",
                "10.0.0.5",
                51000 + i,
                remoteAddr,
                remotePort,
                "ESTABLISHED",
                4242,
                "edge.exe"));
            if (vm.FwActivity?.Rows.Any(r => r.RemoteAddr == remoteAddr && r.RemotePort == remotePort) == true)
            {
                return;
            }

            await Task.Delay(50);
        }

        vm.FwActivity.Should().NotBeNull();
        vm.FwActivity!.Rows.Should().Contain(r => r.RemoteAddr == remoteAddr && r.RemotePort == remotePort);
    }

    private sealed class ShellFirewallEngine : IFirewallEngine
    {
        private bool _outboundBlock;

        public Dictionary<string, FwRule> Rules { get; } = new(StringComparer.Ordinal);

        public bool OutboundBlock
        {
            get => _outboundBlock;
            private set
            {
                _outboundBlock = value;
                PerProfileBlock = new Dictionary<string, bool>(StringComparer.Ordinal)
                {
                    ["Domain"] = value,
                    ["Private"] = value,
                    ["Public"] = value,
                };
            }
        }

        public Dictionary<string, bool> PerProfileBlock { get; private set; } = new(StringComparer.Ordinal)
        {
            ["Domain"] = false,
            ["Private"] = false,
            ["Public"] = false,
        };

        public IReadOnlyList<FwRule> ListRules() => Rules.Values.ToList();

        public IReadOnlyList<FwAppPackage> ListPackages() => Array.Empty<FwAppPackage>();

        public bool CreateRule(FwRule rule)
        {
            if (Rules.ContainsKey(rule.Name))
            {
                return false;
            }

            Rules[rule.Name] = rule;
            return true;
        }

        public bool DeleteRule(string name) => Rules.Remove(name);

        public bool SetRuleEnabled(string name, bool enabled)
        {
            if (!Rules.TryGetValue(name, out var rule))
            {
                return false;
            }

            Rules[name] = rule with { Enabled = enabled };
            return true;
        }

        public bool RuleExists(string name) => Rules.ContainsKey(name);

        public IReadOnlyList<FwProfilePosture> GetPosture() =>
            PerProfileBlock.Select(kv => new FwProfilePosture(kv.Key, true, kv.Value)).ToList();

        public void SetDefaultOutboundBlock(bool block) => OutboundBlock = block;

        public void SetDefaultOutboundBlock(IReadOnlyDictionary<string, bool> perProfile)
        {
            PerProfileBlock = new Dictionary<string, bool>(perProfile, StringComparer.Ordinal);
            _outboundBlock = PerProfileBlock.Values.All(v => v);
        }

        public bool SetRuleProgram(string name, string programPath)
        {
            if (!Rules.TryGetValue(name, out var rule))
            {
                return false;
            }

            Rules[name] = rule with { Program = programPath };
            return true;
        }

        public bool SetRuleRemoteAddresses(string name, string remoteAddresses)
        {
            if (!Rules.TryGetValue(name, out var rule))
            {
                return false;
            }

            Rules[name] = rule with { RemoteAddr = remoteAddresses };
            return true;
        }
    }

    private sealed class ShellFlowTerminator : IFlowTerminator
    {
        public FlowTerminationResult CloseTcp4(FlowTuple flow) =>
            new(true, "closed IPv4 TCP flow");
    }

    private sealed class EmptyListFetcher : IListFetcher
    {
        public Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct) =>
            Task.FromResult(string.Empty);

        public Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct) =>
            Task.FromResult(Array.Empty<byte>());
    }
}
