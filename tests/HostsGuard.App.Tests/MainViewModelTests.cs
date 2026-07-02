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

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_mainvm_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "db.sqlite")));
        var token = SessionToken.Generate();
        var pipe = "HostsGuard.MainVmTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, token, pipe);
        await _app.StartAsync();
        _client = new HostsServiceClient(NamedPipeChannel.Create(token, pipe));
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

    private MainViewModel CreateShell() => new(() => _client, _config, new ThemeManager());

    [Fact]
    public async Task Connect_populates_status_and_hosts_tab()
    {
        await _client.Hosts.BlockAsync(new Contracts.DomainRequest { Domain = "ads.example.com", Source = "manual" });

        var vm = CreateShell();
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
        var vm = new MainViewModel(
            () => throw new IOException("pipe not found"), _config, new ThemeManager());

        await vm.ConnectCommand.ExecuteAsync(null);

        vm.IsConnected.Should().BeFalse();
        vm.ConnectionText.Should().Contain("Service unavailable");
    }

    [Fact]
    public void Theme_toggle_flips_and_persists()
    {
        var vm = CreateShell();
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
        var vm = CreateShell();

        vm.UiScalePct = 125;

        vm.UiScale.Should().Be(1.25);
        var reread = new AppConfigStore(_config.FilePath);
        reread.Load();
        reread.UiScalePct.Should().Be(125);
    }
}
