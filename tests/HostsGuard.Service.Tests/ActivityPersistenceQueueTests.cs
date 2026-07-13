using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

[SupportedOSPlatform("windows")]
public sealed class ActivityPersistenceQueueTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;

    public ActivityPersistenceQueueTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_activity_queue_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "db.sqlite")),
            dataDir: _dir);
    }

    public void Dispose()
    {
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task RecordDns_burst_preserves_live_order_and_persists_in_batches()
    {
        var domains = Enumerable.Range(0, 1000)
            .Select(i => $"burst-{i:D4}.example.com")
            .ToArray();
        domains[7] = "blocked-burst.example.com";
        domains[123] = "hidden-burst.localtest";
        _state.Db.AddDomain(domains[7], "blocked", "manual");
        _state.Db.HideRoot("hidden-burst.localtest");
        using var sub = _state.Bus.Subscribe<DnsEvent>();

        foreach (var domain in domains)
        {
            _state.RecordDns(domain, "edge.exe", 1234);
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        for (var i = 0; i < domains.Length; i++)
        {
            var ev = await sub.Reader.ReadAsync(cts.Token);
            ev.Domain.Should().Be(domains[i]);
            ev.Process.Should().Be("edge.exe");
            ev.Pid.Should().Be(1234);
            if (i == 7)
            {
                ev.Blocked.Should().BeTrue();
            }

            if (i == 123)
            {
                ev.Hidden.Should().BeTrue();
            }
        }

        await _state.FlushActivityPersistenceAsync(cts.Token);

        _state.ActivityPersistence.LargestDnsBatchSize.Should().BeGreaterThan(1);
        _state.ActivityPersistence.WriteBatchCount.Should().BeLessThan(domains.Length);
        _state.Db.GetFeed(1500).Select(r => r.Domain).Should().BeEquivalentTo(domains);
    }

    [Fact]
    public async Task Privacy_excluded_dns_remains_live_but_is_not_persisted()
    {
        _state.Db.UpsertHistoryPrivacyExclusion("domain", "private.example");
        using var sub = _state.Bus.Subscribe<DnsEvent>();
        _state.RecordDns("api.private.example", "browser.exe", 42);

        sub.Reader.TryRead(out var live).Should().BeTrue();
        live!.Domain.Should().Be("api.private.example");
        await _state.FlushActivityPersistenceAsync();
        _state.Db.GetFeed().Should().NotContain(x => x.Domain == "api.private.example");
    }

    [Fact]
    public async Task Flush_persists_every_accepted_sighting_and_counts_saturation_drops()
    {
        // NET-168: under a burst that saturates the bounded queue, a flush must
        // still persist every sighting the queue ACCEPTED (the flush marker can
        // no longer evict a pending write), and any shed sighting is counted, not
        // silently lost. Invariant: persisted + dropped == enqueued.
        const int total = 500;
        var path = Path.Combine(_dir, "flush-sat.db");
        using var db = new HostsDatabase(path);
        using var queue = new ActivityPersistenceQueue(db, capacity: 4, maxBatch: 2);

        for (var i = 0; i < total; i++)
        {
            queue.EnqueueDnsSighting($"sat-{i:D3}.example.com", "edge.exe", null, DateTime.Now);
        }

        await queue.FlushAsync();

        var persisted = db.GetFeed(total + 10).Count;
        persisted.Should().BeGreaterThan(0);
        queue.DroppedWriteCount.Should().BeGreaterThan(0); // the burst provably saturated a 4-slot queue
        (persisted + (int)queue.DroppedWriteCount).Should().Be(total);
    }

    [Fact]
    public void Disposing_queue_drains_pending_dns_writes()
    {
        var path = Path.Combine(_dir, "drain.db");
        using var db = new HostsDatabase(path);
        using (var queue = new ActivityPersistenceQueue(db))
        {
            for (var i = 0; i < 100; i++)
            {
                queue.EnqueueDnsSighting($"drain-{i:D3}.example.com", "edge.exe", null, DateTime.Now);
            }
        }

        db.GetFeed(150).Should().HaveCount(100);
    }
}
