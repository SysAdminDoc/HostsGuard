using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-117: a binary under a user-trusted folder auto-allows without a prompt;
/// binaries outside still prompt; the trusted-folder set persists across restart.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TrustedFolderTests : IDisposable
{
    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly FakeFirewallEngine _fw;

    public TrustedFolderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_folder_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        _fw = new FakeFirewallEngine();
        _state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")),
            _fw,
            new FirewallIdentity(Path.Combine(_dir, "fw_identities.json")),
            dataDir: _dir);
        _state.Consent.SetMode(ConsentBroker.ModeNotify);
    }

    private static BlockedConnection Blocked(string app)
        => new(DateTime.UtcNow, app, "Out", "203.0.113.7", 443, "TCP", 4711, 5157);

    [Fact]
    public void Binary_under_a_trusted_folder_auto_allows()
    {
        _state.Consent.SetTrustedFolders(new[] { @"C:\Apps\Portable" });

        _state.Consent.OnBlocked(Blocked(@"C:\Apps\Portable\v3\tool.exe"));

        _state.Consent.PendingCount.Should().Be(0);
        _fw.Rules.Keys.Should().Contain(k => k.StartsWith("HG_Folder_tool_Out", StringComparison.Ordinal));
    }

    [Fact]
    public void Binary_outside_trusted_folders_prompts()
    {
        _state.Consent.SetTrustedFolders(new[] { @"C:\Apps\Portable" });

        _state.Consent.OnBlocked(Blocked(@"C:\Other\tool.exe"));

        _state.Consent.PendingCount.Should().Be(1);
        _fw.Rules.Keys.Should().NotContain(k => k.StartsWith("HG_Folder_", StringComparison.Ordinal));
    }

    [Fact]
    public void Trusted_folders_persist_across_restart()
    {
        _state.Consent.SetTrustedFolders(new[] { @"C:\Apps\Portable\", @"C:\Apps\Portable" }); // dedup + trailing slash
        _state.Consent.TrustedFolders.Should().ContainSingle().Which.Should().Be(@"C:\Apps\Portable");

        using var reloaded = new ConsentBroker(_state.Db, _state.Bus, _fw, null, _dir);
        reloaded.TrustedFolders.Should().ContainSingle().Which.Should().Be(@"C:\Apps\Portable");
    }

    public void Dispose()
    {
        _state.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
