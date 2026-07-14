using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class ScheduledRefreshLifecycleTests : IDisposable
{
    private sealed class BlockingFetcher : IListFetcher
    {
        private int _calls;

        internal ManualResetEventSlim Started { get; } = new(false);
        internal ManualResetEventSlim Release { get; } = new(false);

        public async Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                Started.Set();
                await Task.Run(() => Release.Wait());
                return "0.0.0.0 drain.example.com";
            }

            throw new InvalidOperationException("no response");
        }

        public Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct)
            => Task.FromResult(Array.Empty<byte>());
    }

    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly HostsEngine _hosts;

    public ScheduledRefreshLifecycleTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_scheduled_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _hosts = new HostsEngine(hostsPath);
    }

    [Fact]
    public async Task List_importer_dispose_drains_scheduled_refresh_and_is_idempotent()
    {
        var fetcher = new BlockingFetcher();
        var importer = new ListImporter(_hosts, _db, fetcher, TimeSpan.FromHours(24));
        _db.UpsertBlocklistSub("drain", "https://lists.example.com/domains.txt", 1);
        importer.KickScheduledRefresh();
        fetcher.Started.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue();

        var dispose = Task.Run(importer.Dispose);
        (await Task.WhenAny(dispose, Task.Delay(200))).Should().NotBe(dispose);
        fetcher.Release.Set();
        await dispose.WaitAsync(TimeSpan.FromSeconds(6));

        importer.Dispose();
        _db.GetBlocklistSub("drain")!.DomainCount.Should().Be(1);
    }

    [Fact]
    public async Task Intelligence_dispose_drains_scheduled_refresh_and_is_idempotent()
    {
        var fetcher = new BlockingFetcher();
        var intelligence = new BlocklistIntelligence(_db, fetcher);
        intelligence.KickScheduledRefresh();
        fetcher.Started.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue();

        var dispose = Task.Run(intelligence.Dispose);
        (await Task.WhenAny(dispose, Task.Delay(200))).Should().NotBe(dispose);
        fetcher.Release.Set();
        await dispose.WaitAsync(TimeSpan.FromSeconds(6));

        intelligence.Dispose();
        _db.GetListIndexStats().Lists.Should().Be(1);
    }

    [Fact]
    public async Task Domain_firewall_dispose_drains_scheduled_refresh_and_is_idempotent()
    {
        using var started = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);
        var coordinator = new DomainFirewallRuleCoordinator(_db, firewall: null,
            resolver: async (_, _) =>
            {
                started.Set();
                await Task.Run(() => release.Wait());
                return new[] { "203.0.113.7" };
            });
        _db.UpsertDomainFirewallRule("api.example.com", @"C:\Apps\app.exe", "HG_Domain_test",
            "Block", enabled: true, remoteAddr: string.Empty);
        coordinator.KickScheduledRefresh();
        started.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue();

        var dispose = Task.Run(coordinator.Dispose);
        (await Task.WhenAny(dispose, Task.Delay(200))).Should().NotBe(dispose);
        release.Set();
        await dispose.WaitAsync(TimeSpan.FromSeconds(6));

        coordinator.Dispose();
    }

    public void Dispose()
    {
        _db.Dispose();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }
}
