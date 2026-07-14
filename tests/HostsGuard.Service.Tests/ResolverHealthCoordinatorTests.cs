using FluentAssertions;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

public sealed class ResolverHealthCoordinatorTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "hg_resolver_health_" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Opt_in_schedule_persists_and_scheduled_run_is_cached()
    {
        Directory.CreateDirectory(_dir);
        using var db = new HostsDatabase(Path.Combine(_dir, "state.db"));
        var dns = new FakeDnsConfig
        {
            ResolverHealthResults =
            [
                new DnsResolverHealthResult(
                    "vpn-id", "Work VPN", "10.0.0.53", DnsResolverProtocol.Udp,
                    new DnsResolverAddressResult(DnsResolverProbeStatus.Available, 1, "ok"),
                    new DnsResolverAddressResult(DnsResolverProbeStatus.Available, 1, "ok"),
                    TimeSpan.FromMilliseconds(11), DnsResolverTlsStatus.NotApplicable, string.Empty),
            ],
        };

        using (var coordinator = new ResolverHealthCoordinator(dns, db))
        {
            coordinator.Snapshot().ScheduleEnabled.Should().BeFalse();
            coordinator.ConfigureSchedule(true, 30).ScheduleEnabled.Should().BeTrue();
            await coordinator.TriggerScheduledForTestAsync();
            var cached = coordinator.Snapshot();
            cached.Source.Should().Be("scheduled");
            cached.Host.Should().Be(ResolverHealthCoordinator.DefaultProbeHost);
            cached.Entries.Should().ContainSingle();
        }

        using var restarted = new ResolverHealthCoordinator(dns, db);
        restarted.Snapshot().ScheduleEnabled.Should().BeTrue();
        restarted.Snapshot().ScheduleIntervalMinutes.Should().Be(30);
        restarted.Snapshot().NextScheduledAtUtc.Should().NotBeNull();
    }

    [Fact]
    public async Task Caller_cancellation_clears_running_state_and_retains_cached_result()
    {
        Directory.CreateDirectory(_dir);
        using var db = new HostsDatabase(Path.Combine(_dir, "cancel.db"));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dns = new FakeDnsConfig
        {
            ResolverHealthCheck = async (_, _, cancellationToken) =>
            {
                entered.SetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return [];
            },
        };
        using var coordinator = new ResolverHealthCoordinator(dns, db);
        using var cancellation = new CancellationTokenSource();

        var run = coordinator.RunManualAsync("example.com", cancellation.Token);
        await entered.Task;
        coordinator.Snapshot().Running.Should().BeTrue();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        coordinator.Snapshot().Running.Should().BeFalse();
        coordinator.Snapshot().Message.Should().Contain("cancelled");
        coordinator.Snapshot().CheckedAtUtc.Should().BeNull();
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }
}
