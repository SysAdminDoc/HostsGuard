using System.Runtime.Versioning;
using FluentAssertions;
using Xunit;

namespace HostsGuard.Windows.Tests;

/// <summary>
/// NET-203: the DNS-path registry baseline. The diff is pure and drives the
/// tamper alert, so it is unit-tested with simulated before/after snapshots;
/// Snapshot() is smoke-tested for the current machine.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DnsRegistryBaselineTests
{
    [Fact]
    public void Identical_snapshots_report_no_change()
    {
        var baseline = new Dictionary<string, string>
        {
            ["DNSClient\\DoHPolicy"] = "(absent)",
            ["Tcpip\\Parameters\\NameServer"] = "",
        };

        DnsRegistryBaseline.Diff(baseline, new Dictionary<string, string>(baseline)).Should().BeEmpty();
    }

    [Fact]
    public void A_changed_value_is_reported_with_before_and_after()
    {
        var baseline = new Dictionary<string, string> { ["DNSClient\\DoHPolicy"] = "(absent)" };
        var current = new Dictionary<string, string> { ["DNSClient\\DoHPolicy"] = "3" };

        var changes = DnsRegistryBaseline.Diff(baseline, current);

        changes.Should().ContainSingle();
        changes[0].Key.Should().Be("DNSClient\\DoHPolicy");
        changes[0].Before.Should().Be("(absent)");
        changes[0].After.Should().Be("3");
    }

    [Fact]
    public void An_appearing_or_disappearing_key_is_treated_as_a_change()
    {
        var baseline = new Dictionary<string, string> { ["Tcpip\\Parameters\\NameServer"] = "9.9.9.9" };
        var current = new Dictionary<string, string> { ["DNSClient\\DoHPolicy"] = "2" };

        var changes = DnsRegistryBaseline.Diff(baseline, current);

        changes.Should().HaveCount(2);
        changes.Should().Contain(c => c.Key == "Tcpip\\Parameters\\NameServer" && c.Before == "9.9.9.9" && c.After == "(absent)");
        changes.Should().Contain(c => c.Key == "DNSClient\\DoHPolicy" && c.Before == "(absent)" && c.After == "2");
    }

    [Fact]
    public void Snapshot_reads_every_watched_key_without_throwing()
    {
        var snapshot = DnsRegistryBaseline.Snapshot();

        snapshot.Should().NotBeEmpty();
        snapshot.Values.Should().OnlyContain(v => v != null);
    }
}
