using System.IO.Compression;
using System.Runtime.Versioning;
using FluentAssertions;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-202: offline ASN attribution via a DB-IP IP-to-ASN Lite MMDB. Mirrors the
/// GeoIP guards — an absent database degrades to blank, a corrupt download never
/// replaces working state — plus record formatting, unit-tested without an MMDB.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AsnServiceTests : IDisposable
{
    private readonly string _dir;

    public AsnServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_asn_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void Absent_database_degrades_to_blank_not_crashing()
    {
        using var asn = new AsnService(_dir);
        asn.IsLoaded.Should().BeFalse();
        asn.Lookup("8.8.8.8").Should().BeEmpty();
    }

    [Theory]
    [InlineData(15169L, "Google LLC", "AS15169 Google LLC")]
    [InlineData(13335L, "Cloudflare, Inc.", "AS13335 Cloudflare, Inc.")]
    public void Format_renders_number_and_org(long number, string org, string expected)
    {
        var record = new Dictionary<string, object>
        {
            ["autonomous_system_number"] = number,
            ["autonomous_system_organization"] = org,
        };

        AsnService.Format(record).Should().Be(expected);
    }

    [Fact]
    public void Format_tolerates_number_only_and_org_only()
    {
        AsnService.Format(new Dictionary<string, object> { ["autonomous_system_number"] = 64500L })
            .Should().Be("AS64500");
        AsnService.Format(new Dictionary<string, object> { ["autonomous_system_organization"] = "Some Net" })
            .Should().Be("Some Net");
    }

    [Fact]
    public void Format_of_empty_or_null_record_is_blank()
    {
        AsnService.Format(null).Should().BeEmpty();
        AsnService.Format(new Dictionary<string, object>()).Should().BeEmpty();
    }

    [Fact]
    public async Task Corrupt_asn_download_never_replaces_state()
    {
        var junk = new byte[2048];
        Random.Shared.NextBytes(junk);
        using var compressed = new MemoryStream();
        using (var gz = new GZipStream(compressed, CompressionMode.Compress, leaveOpen: true))
        {
            gz.Write(junk);
        }

        var fetcher = new FakeListFetcher();
        fetcher.BinaryResponses[AsnService.DefaultUrl] = compressed.ToArray();

        using var asn = new AsnService(_dir);
        var act = async () => await asn.RefreshAsync(fetcher, url: null, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>();
        asn.IsLoaded.Should().BeFalse();
        File.Exists(Path.Combine(_dir, "asn.mmdb")).Should().BeFalse();
    }
}
