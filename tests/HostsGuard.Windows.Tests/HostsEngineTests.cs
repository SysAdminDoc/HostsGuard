using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

public sealed class HostsEngineTests : IDisposable
{
    private readonly string _dir;
    private readonly string _hosts;

    public HostsEngineTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_hosts_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hosts = Path.Combine(_dir, "hosts");
        File.WriteAllText(_hosts, "# custom header\n127.0.0.1 myserver\n\n");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    private HostsEngine New() => new(_hosts);

    [Fact]
    public void Block_adds_domain_and_persists()
    {
        var e = New();
        e.Block("ads.example.com").Should().BeTrue();
        e.GetBlocked().Should().Contain("ads.example.com");
        // Re-read from disk via a fresh engine.
        New().GetBlocked().Should().Contain("ads.example.com");
    }

    [Fact]
    public void Block_is_idempotent_and_validates()
    {
        var e = New();
        e.Block("ads.example.com").Should().BeTrue();
        e.Block("ads.example.com").Should().BeFalse(); // already blocked
        e.Block("not a domain").Should().BeFalse();     // invalid
        e.Block("192.168.1.1").Should().BeFalse();       // IP is not a blockable domain
    }

    [Fact]
    public void Unblock_removes_only_that_domain_and_preserves_custom()
    {
        var e = New();
        e.BlockBulk(new[] { "a.com", "b.com" }).Should().Be(2);
        e.Unblock("a.com").Should().BeTrue();
        e.GetBlocked().Should().NotContain("a.com").And.Contain("b.com");
        // Custom non-managed mapping preserved.
        e.GetLines().Should().Contain(l => l.Contains("myserver"));
    }

    [Fact]
    public void Reconcile_enforces_exact_set_preserving_custom_lines()
    {
        var e = New();
        e.BlockBulk(new[] { "old1.com", "old2.com" });
        var (added, target) = e.Reconcile(new[] { "old1.com", "new1.com" });
        added.Should().Be(1);   // new1
        target.Should().Be(2);
        var blocked = e.GetBlocked();
        blocked.Should().Contain(new[] { "old1.com", "new1.com" });
        blocked.Should().NotContain("old2.com");
        // Non-managed entries survive.
        e.GetLines().Should().Contain(l => l.Contains("myserver"));
        e.GetLines().Should().Contain(l => l.Contains("# custom header"));
    }

    [Fact]
    public void EmergencyReset_leaves_only_header_and_no_blocks()
    {
        var e = New();
        e.BlockBulk(new[] { "a.com", "b.com" });
        e.EmergencyReset();
        e.GetBlocked().Should().BeEmpty();
        e.GetLines().Should().Contain(l => l.Contains("Microsoft"));
    }

    [Fact]
    public void SelfChange_recognizes_our_write_once()
    {
        var e = New();
        e.Block("x.example.com");
        var hash = e.CurrentFileHash();
        e.IsSelfChange(hash).Should().BeTrue();  // our write
        e.IsSelfChange(hash).Should().BeFalse(); // consumed — a second detection is treated as external
        e.IsSelfChange(null).Should().BeFalse();
    }

    [Fact]
    public void External_edit_is_not_a_self_change()
    {
        var e = New();
        e.Block("x.example.com");
        // Simulate an external tamper by writing directly, bypassing the engine.
        File.AppendAllText(_hosts, "0.0.0.0 evil.example.com\n");
        var hash = e.CurrentFileHash();
        e.IsSelfChange(hash).Should().BeFalse();
    }

    // Property/fuzz: Reconcile never loses non-managed lines and always yields exactly the target set.
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(42)]
    [InlineData(1234)]
    public void Reconcile_property_preserves_custom_and_matches_target(int seed)
    {
        var rng = new Random(seed);
        var custom = new List<string> { "# preserve me", "127.0.0.1 keepserver", "0.0.0.0 not_a_domain_line_kept?" };
        File.WriteAllText(_hosts, string.Join('\n', custom) + "\n");

        var e = New();
        // Random churn.
        for (var i = 0; i < 20; i++)
        {
            e.Block($"d{rng.Next(30)}.example.com");
        }

        var target = Enumerable.Range(0, rng.Next(1, 25)).Select(i => $"t{i}.example.com").ToList();
        e.Reconcile(target);

        var blocked = e.GetBlocked();
        blocked.Should().BeEquivalentTo(target); // exactly the target set
        var lines = e.GetLines();
        lines.Should().Contain(l => l.Contains("# preserve me"));
        lines.Should().Contain(l => l.Contains("keepserver"));
    }
}
