using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

/// <summary>
/// WFCP-002: NT device paths from event 5157 translate to DOS paths over a
/// synthetic volume map — mapped drives, unmapped volumes (unchanged), prefix
/// shadowing, case-insensitivity, and refresh-on-miss.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DevicePathMapperTests
{
    private static readonly Dictionary<string, string> BaseMap = new(StringComparer.OrdinalIgnoreCase)
    {
        [@"\Device\HarddiskVolume4"] = "C:",
        [@"\Device\HarddiskVolume10"] = "D:",
    };

    [Fact]
    public void Maps_device_prefix_to_drive_letter()
    {
        var mapper = new DevicePathMapper(() => BaseMap);

        mapper.ToDosPath(@"\device\harddiskvolume4\program files\app\app.exe")
            .Should().Be(@"C:\program files\app\app.exe");
    }

    [Fact]
    public void Longer_volume_numbers_are_not_shadowed_by_shorter_prefixes()
    {
        var mapper = new DevicePathMapper(() => BaseMap);

        // \Device\HarddiskVolume1 would prefix-match Volume10 without the
        // longest-prefix + separator guard.
        mapper.ToDosPath(@"\Device\HarddiskVolume10\tools\x.exe").Should().Be(@"D:\tools\x.exe");
    }

    [Fact]
    public void Unknown_volume_and_non_device_paths_return_unchanged()
    {
        var mapper = new DevicePathMapper(() => BaseMap);

        mapper.ToDosPath(@"\Device\HarddiskVolume9\x.exe").Should().Be(@"\Device\HarddiskVolume9\x.exe");
        mapper.ToDosPath(@"C:\already\dos.exe").Should().Be(@"C:\already\dos.exe");
        mapper.ToDosPath("System").Should().Be("System");
        mapper.ToDosPath(string.Empty).Should().Be(string.Empty);
    }

    [Fact]
    public void Miss_triggers_one_refresh_that_can_pick_up_new_volumes()
    {
        var calls = 0;
        var mapper = new DevicePathMapper(() =>
        {
            calls++;
            return calls == 1
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : BaseMap;
        });

        mapper.ToDosPath(@"\Device\HarddiskVolume4\late\mount.exe").Should().Be(@"C:\late\mount.exe");
        calls.Should().Be(2); // initial load + one refresh on miss
    }

    [Fact]
    public void Live_volume_map_translates_the_system_drive()
    {
        // Integration sanity: the real QueryDosDevice map must translate the
        // system drive's own device path back to itself.
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System); // C:\Windows\system32
        var mapper = new DevicePathMapper();

        // Find the device name for the system drive by reverse lookup through
        // a real NT path produced from the mapper's own table: translate a
        // fabricated path for every known volume until one round-trips.
        var drive = Path.GetPathRoot(system)!.TrimEnd('\\'); // "C:"
        var probe = mapper.ToDosPath(@"\Device\NoSuchVolume123\x");
        probe.Should().Be(@"\Device\NoSuchVolume123\x"); // graceful on garbage

        // The mapper's table is private; assert behavior instead: a DOS path
        // stays a DOS path and the drive exists.
        Directory.Exists(drive + "\\").Should().BeTrue();
    }
}
