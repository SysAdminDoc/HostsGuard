using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

/// <summary>
/// NET-073: SCM enumeration smoke (needs no elevation) and the sole-owner
/// disambiguation contract.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceAttributionTests
{
    [Fact]
    public void Snapshot_maps_running_services_to_pids()
    {
        var map = ServiceAttribution.Snapshot();

        // Any Windows box has running services; every entry carries a key name.
        map.Should().NotBeEmpty();
        map.Values.SelectMany(v => v).Should().OnlyContain(o => o.Key.Length > 0 && o.Display.Length > 0);
    }

    [Fact]
    public void System_and_idle_pids_never_attribute()
    {
        var attribution = new ServiceAttribution();

        attribution.DisplayFor(0).Should().BeEmpty();
        attribution.DisplayFor(4).Should().BeEmpty();
        attribution.SoleOwner(0).Should().BeNull();
    }

    [Fact]
    public void A_running_service_pid_resolves_to_its_display_name()
    {
        var attribution = new ServiceAttribution();
        var map = ServiceAttribution.Snapshot();
        var (pid, owners) = map.First();

        var display = attribution.DisplayFor(pid);

        display.Should().NotBeEmpty();
        owners.Select(o => o.Display).Should().Contain(n => display.Contains(n));
    }
}
