using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class SchedulingTests
{
    [Theory]
    [InlineData("10:00", "09:00", "17:00", true)]
    [InlineData("08:00", "09:00", "17:00", false)]
    [InlineData("17:00", "09:00", "17:00", false)] // end exclusive
    [InlineData("23:30", "22:00", "06:00", true)]  // overnight
    [InlineData("05:00", "22:00", "06:00", true)]
    [InlineData("12:00", "22:00", "06:00", false)]
    [InlineData("06:00", "22:00", "06:00", false)]
    [InlineData("00:00", "00:00", "00:00", false)] // zero window
    public void InWindow_matches_python(string now, string start, string end, bool expected) =>
        Scheduling.InWindow(now, start, end).Should().Be(expected);
}

public class ReasonsTests
{
    [Theory]
    [InlineData("blocked", "", "blocked", "Blocked by hosts", "hosts_file")]
    [InlineData("", "list:HaGezi", "blocked", "", "blocklist")]
    [InlineData("", "service:youtube", "blocked", "", "service")]
    [InlineData("whitelisted", "", "whitelisted", "", "allowlist")]
    [InlineData("", "", "fw_blocked", "", "firewall")]
    [InlineData("", "", "", "Encrypted DNS block", "doh")]
    [InlineData("", "", "", "telemetry endpoint", "telemetry")]
    [InlineData("schedule", "", "", "", "schedule")]
    [InlineData("", "", "blocked", "", "manual")]
    [InlineData("", "", "", "", "unknown")]
    public void Canonical_matches_python(string reason, string source, string action, string details, string expected) =>
        Reasons.Canonical(reason, source, action, details).Should().Be(expected);

    [Fact]
    public void Label_falls_back_to_unknown() =>
        Reasons.Label("nonsense-reason-xyz").Should().Be("Unknown");

    [Fact]
    public void Label_maps_canonical() =>
        Reasons.Label("list").Should().Be("Blocklist");
}
