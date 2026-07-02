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
/// Proves the UI layer "connects to the service and drives it": a real
/// HostsViewModel → HostsServiceClient → named-pipe gRPC → live service impls →
/// HostsEngine + DB. (Visual XAML rendering needs an interactive desktop session
/// and is out of scope for a headless unit run.)
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HostsViewModelTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private HostsServiceClient _client = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_appvm_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");

        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "db.sqlite")));
        var token = SessionToken.Generate();
        var pipe = "HostsGuard.AppVmTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, token, pipe);
        await _app.StartAsync();
        _client = new HostsServiceClient(NamedPipeChannel.Create(token, pipe));
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task Block_command_writes_through_service_and_refreshes_grid()
    {
        var vm = new HostsViewModel(_client) { NewDomain = "ads.example.com" };

        await vm.BlockCommand.ExecuteAsync(null);

        vm.Domains.Should().Contain(d => d.Domain == "ads.example.com" && d.Status == "blocked");
        vm.StatusText.Should().Contain("domains");
        _state.Hosts.GetBlocked().Should().Contain("ads.example.com");
    }

    [Fact]
    public async Task Refresh_filter_scopes_the_grid()
    {
        await new HostsViewModel(_client) { NewDomain = "keep.me.com" }.BlockCommand.ExecuteAsync(null);
        await new HostsViewModel(_client) { NewDomain = "other.site.com" }.BlockCommand.ExecuteAsync(null);

        var vm = new HostsViewModel(_client) { Filter = "keep" };
        await vm.RefreshCommand.ExecuteAsync(null);

        vm.Domains.Should().OnlyContain(d => d.Domain.Contains("keep"));
    }

    [Fact]
    public async Task Unblock_removes_from_service_and_grid()
    {
        var block = new HostsViewModel(_client) { NewDomain = "gone.example.com" };
        await block.BlockCommand.ExecuteAsync(null);

        var vm = new HostsViewModel(_client);
        await vm.UnblockCommand.ExecuteAsync("gone.example.com");

        vm.Domains.Should().NotContain(d => d.Domain == "gone.example.com");
        _state.Hosts.GetBlocked().Should().NotContain("gone.example.com");
    }
}
