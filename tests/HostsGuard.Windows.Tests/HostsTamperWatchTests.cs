using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

[SupportedOSPlatform("windows")]
public sealed class HostsTamperWatchTests : IDisposable
{
    private readonly string _dir;
    private readonly string _hosts;

    public HostsTamperWatchTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_watch_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hosts = Path.Combine(_dir, "hosts");
        File.WriteAllText(_hosts, "# hosts\n");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void External_edit_fires_and_self_write_is_suppressed()
    {
        var engine = new HostsEngine(_hosts);
        using var watch = new HostsTamperWatch(engine);
        using var external = new ManualResetEventSlim(false);
        watch.ExternalChangeDetected += (_, _) => external.Set();
        watch.Start();

        // External tamper: write directly, bypassing the engine.
        File.AppendAllText(_hosts, "0.0.0.0 evil.example.com\n");
        external.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue("an external hosts edit must be detected");

        // Let events settle, then perform a legitimate engine write.
        Thread.Sleep(300);
        external.Reset();
        engine.Block("good.example.com").Should().BeTrue();

        // A self-write must NOT raise the external-change event.
        external.Wait(TimeSpan.FromSeconds(2)).Should().BeFalse("the engine's own write must be recognized via the self-write hash");
    }

    [Fact]
    public void Registry_databasepath_is_not_tampered_on_a_normal_machine()
    {
        // On any healthy machine DataBasePath points at ...\drivers\etc, so no tamper.
        HostsTamperWatch.CheckRegistryTamper().Should().BeNull();
    }
}
