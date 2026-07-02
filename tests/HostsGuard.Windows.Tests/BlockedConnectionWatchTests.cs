using System.Runtime.Versioning;
using System.Security.Principal;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

/// <summary>
/// WFCP-003: 5157/5152 parsing is pure and locale-safe; the Security-log
/// subscription and audit-policy enable are admin-gated and degrade gracefully
/// when unelevated.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class BlockedConnectionWatchTests
{
    private static readonly DevicePathMapper Mapper = new(() =>
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [@"\Device\HarddiskVolume4"] = "C:",
        });

    private const string Sample5157Xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" />
            <EventID>5157</EventID>
          </System>
          <EventData>
            <Data Name="ProcessID">4711</Data>
            <Data Name="Application">\device\harddiskvolume4\program files\app\app.exe</Data>
            <Data Name="Direction">%%14593</Data>
            <Data Name="SourceAddress">192.168.1.10</Data>
            <Data Name="SourcePort">53211</Data>
            <Data Name="DestAddress">203.0.113.9</Data>
            <Data Name="DestPort">443</Data>
            <Data Name="Protocol">6</Data>
            <Data Name="FilterRTID">67338</Data>
            <Data Name="LayerName">%%14611</Data>
            <Data Name="LayerRTID">48</Data>
          </EventData>
        </Event>
        """;

    [Fact]
    public void Parses_5157_into_a_dos_resolved_outbound_block()
    {
        var fields = BlockedConnectionWatch.ParseEventXml(Sample5157Xml);
        var ts = new DateTime(2026, 7, 2, 10, 0, 0, DateTimeKind.Utc);

        var blocked = BlockedConnectionWatch.FromFields(fields, 5157, ts, Mapper);

        blocked.Should().NotBeNull();
        blocked!.Application.Should().Be(@"C:\program files\app\app.exe");
        blocked.Direction.Should().Be("Out");
        blocked.RemoteAddress.Should().Be("203.0.113.9");
        blocked.RemotePort.Should().Be(443);
        blocked.Protocol.Should().Be("TCP");
        blocked.ProcessId.Should().Be(4711);
        blocked.EventId.Should().Be(5157);
    }

    [Fact]
    public void Inbound_direction_and_udp_protocol_map_correctly()
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Application"] = @"\device\harddiskvolume4\svc.exe",
            ["Direction"] = "%%14592",
            ["DestAddress"] = "198.51.100.4",
            ["DestPort"] = "53",
            ["Protocol"] = "17",
            ["ProcessID"] = "8",
        };

        var blocked = BlockedConnectionWatch.FromFields(
            fields, 5152, DateTime.UtcNow, Mapper);

        blocked!.Direction.Should().Be("In");
        blocked.Protocol.Should().Be("UDP");
        blocked.EventId.Should().Be(5152);
    }

    [Fact]
    public void Events_without_an_application_are_dropped()
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["DestAddress"] = "198.51.100.4",
        };

        BlockedConnectionWatch.FromFields(fields, 5157, DateTime.UtcNow, Mapper).Should().BeNull();
    }

    [Fact]
    public void Unmapped_volume_keeps_the_device_path_for_display()
    {
        var fields = BlockedConnectionWatch.ParseEventXml(Sample5157Xml
            .Replace("harddiskvolume4", "harddiskvolume9"));

        var blocked = BlockedConnectionWatch.FromFields(fields, 5157, DateTime.UtcNow, Mapper);

        blocked!.Application.Should().StartWith(@"\device\harddiskvolume9");
    }

    [Fact]
    public void Start_never_throws_and_stop_tears_down_cleanly()
    {
        // Security-log read access varies by machine (admin token, Event Log
        // Readers membership, CustomSD) — assert the graceful contract, not a
        // specific privilege outcome.
        var logs = new List<string>();
        using var watch = new BlockedConnectionWatch(Mapper, _ => { }, logs.Add);
        var started = watch.Start();

        if (started)
        {
            watch.IsActive.Should().BeTrue();
            watch.Start().Should().BeTrue(); // idempotent
            watch.Stop();
            watch.IsActive.Should().BeFalse();
        }
        else
        {
            watch.IsActive.Should().BeFalse();
            logs.Should().ContainSingle(l => l.Contains("unavailable"));
        }
    }

    [Fact]
    public void Audit_policy_enable_is_admin_gated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            // Admin-gated: enabling audit policy requires SeSecurityPrivilege.
            return;
        }

        BlockedConnectionWatch.EnableAuditPolicy().Should().BeTrue();
    }
}
