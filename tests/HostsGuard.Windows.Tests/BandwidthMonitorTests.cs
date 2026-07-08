using System.Net;
using System.Reflection;
using FluentAssertions;
using HostsGuard.Windows;

namespace HostsGuard.Windows.Tests;

public sealed class BandwidthMonitorTests
{
    private static readonly MethodInfo AddMethod =
        typeof(BandwidthMonitor).GetMethod("Add", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingMethodException(nameof(BandwidthMonitor), "Add");

    private static readonly FieldInfo AddressTextCacheField =
        typeof(BandwidthMonitor).GetField("_addressTextCache", BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(nameof(BandwidthMonitor), "_addressTextCache");

    [Fact]
    public void Remote_endpoint_text_cache_reuses_equal_ip_addresses()
    {
        using var monitor = new BandwidthMonitor("HostsGuardBandwidthTest");
        var first = IPAddress.Parse("203.0.113.77");
        var sameAddress = IPAddress.Parse("203.0.113.77");

        AddRemote(monitor, 4242, sent: 10, recv: 0, first);
        AddRemote(monitor, 4242, sent: 0, recv: 20, sameAddress);

        CacheCount(monitor).Should().Be(1);
        var endpoints = monitor.DrainByEndpoint();
        endpoints.Should().ContainKey((4242, "203.0.113.77"));
        endpoints[(4242, "203.0.113.77")].Should().Be((10, 20));
    }

    private static void AddRemote(BandwidthMonitor monitor, int pid, long sent, long recv, IPAddress remote)
        => AddMethod.Invoke(monitor, new object?[] { pid, sent, recv, remote });

    private static int CacheCount(BandwidthMonitor monitor)
    {
        var cache = AddressTextCacheField.GetValue(monitor) ?? throw new InvalidOperationException("cache missing");
        var count = cache.GetType().GetProperty("Count")?.GetValue(cache);
        return count is int value ? value : throw new InvalidOperationException("cache count missing");
    }
}
