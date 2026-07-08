using System.IO;
using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.App.Services;
using HostsGuard.App.ViewModels;
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

        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "db.sqlite")));
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
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private HostsServiceClient CreateClient() => new(NamedPipeChannel.Create(_token, _pipe));

    private MainViewModel CreateShell() => new(CreateClient, _config, new ThemeManager(), new FakeConfirm(true));

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
        vm.Hosts!.Domains.Should().ContainSingle(d => d.Domain == "ads.example.com");
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
    public async Task Reconnect_recreates_client_after_token_rotation_and_restores_live_feeds()
    {
        using var vm = CreateShell();
        await vm.ConnectCommand.ExecuteAsync(null);
        vm.IsConnected.Should().BeTrue();
        var firstActivity = vm.Activity;
        var firstFwActivity = vm.FwActivity;

        await RotateServiceTokenAsync();
        await vm.ConnectCommand.ExecuteAsync(null);

        vm.IsConnected.Should().BeTrue();
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
}
