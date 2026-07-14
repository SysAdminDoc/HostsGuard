using System.Text.Json;
using FluentAssertions;

namespace HostsGuard.Service.Tests;

public sealed class DohIntelligenceTests : IDisposable
{
    private readonly string _dir;

    public DohIntelligenceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_doh_cache_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void CurrentIps_uses_short_file_stat_ttl_and_save_invalidates()
    {
        var clock = new TestClock(DateTime.UtcNow);
        var doh = new DohIntelligence(_dir, TimeSpan.FromHours(1), clock);
        doh.Import(new DohState { Ips = { "203.0.113.10" } });

        doh.CurrentIps().Should().Contain("203.0.113.10");
        WriteState(doh.FilePath, "203.0.113.11");
        File.SetLastWriteTimeUtc(doh.FilePath, DateTime.UtcNow.AddMinutes(1));

        doh.CurrentIps().Should().Contain("203.0.113.10");
        doh.CurrentIps().Should().NotContain("203.0.113.11");

        clock.Advance(TimeSpan.FromHours(1) - TimeSpan.FromTicks(1));
        doh.CurrentIps().Should().Contain("203.0.113.10");
        clock.Advance(TimeSpan.FromTicks(1));
        doh.CurrentIps().Should().Contain("203.0.113.11");
        doh.CurrentIps().Should().NotContain("203.0.113.10");

        var noTtl = new DohIntelligence(_dir, TimeSpan.Zero, clock);
        noTtl.CurrentIps().Should().Contain("203.0.113.11");

        doh.Import(new DohState { Ips = { "203.0.113.12" } });
        doh.CurrentIps().Should().Contain("203.0.113.12");
        doh.CurrentIps().Should().NotContain("203.0.113.10");
    }

    private static void WriteState(string path, string ip)
    {
        File.WriteAllText(path, JsonSerializer.Serialize(new DohState { Ips = { ip } }));
    }
}
