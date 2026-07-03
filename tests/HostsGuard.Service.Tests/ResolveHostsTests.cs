using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// Persistent reverse-DNS: the ResolveHosts RPC serves remembered hosts from
/// the store without touching the network, forward resolutions persist, and
/// published connections auto-fill their host from the store.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ResolveHostsTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private string _pipe = null!;
    private string _token = null!;

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_resolve_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "db.sqlite")),
            dataDir: _dir);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.ResolveTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task ResolveHosts_serves_remembered_hosts_without_reverse_dns()
    {
        // A remembered IP is answered from the store — no network lookup.
        _state.Db.UpsertResolvedHost("203.0.113.9", "cdn.example.com", "dns");
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var dns = new DnsControl.DnsControlClient(channel);

        var request = new ResolveHostsRequest();
        request.Addresses.Add("203.0.113.9");
        var result = await dns.ResolveHostsAsync(request);

        result.Hosts.Single().Host.Should().Be("cdn.example.com");
    }

    [Fact]
    public void RememberResolution_persists_forward_dns_for_reuse()
    {
        _state.RememberResolution("images.example.com", new[] { "203.0.113.20", "203.0.113.21" });

        _state.Db.GetResolvedHost("203.0.113.20").Should().Be("images.example.com");
        _state.ResolveKnownHost("203.0.113.21").Should().Be("images.example.com");
    }

    [Fact]
    public async Task Published_connections_auto_fill_host_from_the_persistent_store()
    {
        _state.Db.UpsertResolvedHost("203.0.113.30", "tracker.example.net", "ptr");
        using var sub = _state.Bus.Subscribe<ConnectionEvent>();

        _state.PublishConnection(new ConnectionInfo("TCP", "127.0.0.1", 5000, "203.0.113.30", 443, "ESTABLISHED", 7, "app.exe"));

        var ev = await sub.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        ev.Host.Should().Be("tracker.example.net");
    }
}
