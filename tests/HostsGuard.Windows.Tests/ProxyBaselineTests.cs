using System.Runtime.Versioning;
using FluentAssertions;
using Xunit;

namespace HostsGuard.Windows.Tests;

[SupportedOSPlatform("windows")]
public sealed class ProxyBaselineTests
{
    [Fact]
    public void Capture_orders_per_user_and_machine_entries_stably()
    {
        var machine = Entry(ProxyStateScope.WinHttpMachine, "machine", enabled: true, "proxy:8080");
        var source = new FakeSource(
            [
                Entry(ProxyStateScope.WinInetUser, "S-1-5-21-2", enabled: false, string.Empty),
                Entry(ProxyStateScope.WinInetUser, "S-1-5-21-1", enabled: true, "one:80"),
            ],
            machine);

        var snapshot = new ProxyBaselineSnapshotter(source).Capture();

        snapshot.Entries.Select(e => (e.Scope, e.Identity)).Should().Equal(
            (ProxyStateScope.WinInetUser, "S-1-5-21-1"),
            (ProxyStateScope.WinInetUser, "S-1-5-21-2"),
            (ProxyStateScope.WinHttpMachine, "machine"));
    }

    [Fact]
    public void Diff_reports_modified_added_and_removed_scopes()
    {
        var before = new ProxyBaselineSnapshot(
        [
            Entry(ProxyStateScope.WinInetUser, "S-1-5-21-1", enabled: false, string.Empty),
            Entry(ProxyStateScope.WinInetUser, "S-1-5-21-2", enabled: true, "old:80"),
            Entry(ProxyStateScope.WinHttpMachine, "machine", enabled: false, string.Empty),
        ]);
        var after = new ProxyBaselineSnapshot(
        [
            Entry(ProxyStateScope.WinInetUser, "S-1-5-21-1", enabled: true, "new:80"),
            Entry(ProxyStateScope.WinInetUser, "S-1-5-21-3", enabled: false, string.Empty),
            Entry(ProxyStateScope.WinHttpMachine, "machine", enabled: false, string.Empty),
        ]);

        var changes = ProxyBaselineSnapshotter.Diff(before, after);

        changes.Should().HaveCount(3);
        changes.Should().Contain(c => c.Identity == "S-1-5-21-1" && c.Before != null && c.After != null);
        changes.Should().Contain(c => c.Identity == "S-1-5-21-2" && c.Before != null && c.After == null);
        changes.Should().Contain(c => c.Identity == "S-1-5-21-3" && c.Before == null && c.After != null);
        changes.Should().NotContain(c => c.Scope == ProxyStateScope.WinHttpMachine);
    }

    [Fact]
    public void Diff_rejects_duplicate_scope_identities()
    {
        var duplicate = Entry(ProxyStateScope.WinHttpMachine, "machine", enabled: false, string.Empty);
        var snapshot = new ProxyBaselineSnapshot([duplicate, duplicate]);

        var action = () => ProxyBaselineSnapshotter.Diff(snapshot, new ProxyBaselineSnapshot([]));

        action.Should().Throw<ArgumentException>().WithMessage("*Duplicate proxy snapshot entry*");
    }

    [Fact]
    public void Advanced_winhttp_json_is_normalized_and_secrets_are_not_exposed()
    {
        const string output = """
            Current WinHTTP advanced proxy settings:
            {
                "ProxyIsEnabled": true,
                "Proxy": "http=user:password@proxy.example:8080;https=https://token@secure.example:8443",
                "ProxyBypass": "<local>;*.corp.example",
                "AutoConfigIsEnabled": true,
                "AutoConfigUrl": "https://pac-user:pac-password@config.example/proxy.pac?token=secret#fragment",
                "AutoDetect": true,
                "PerUserProxySettings": false
            }
            """;

        var parsed = ProxyStateNormalizer.TryParseWinHttpAdvancedJson(output, out var settings);

        parsed.Should().BeTrue();
        settings.Should().BeEquivalentTo(new
        {
            ProxyEnabled = true,
            ProxyServer = "http=[redacted]@proxy.example:8080;https=https://[redacted]@secure.example:8443",
            ProxyBypass = "<local>;*.corp.example",
            AutoConfigEnabled = true,
            AutoConfigUrl = "https://config.example/proxy.pac",
            AutoDetect = true,
            PerUserProxySettings = false,
            Available = true,
            Error = string.Empty,
        });
        settings.Fingerprint.Should().MatchRegex("^[0-9a-f]{64}$");
        settings.ToString().Should().NotContain("password").And.NotContain("secret").And.NotContain("token@");
    }

    [Fact]
    public void Fingerprint_detects_a_change_hidden_by_redaction()
    {
        var first = ProxyStateNormalizer.Create(
            true,
            "alice:first@proxy.example:8080",
            string.Empty,
            true,
            "https://config.example/proxy.pac?token=first",
            false,
            true);
        var second = ProxyStateNormalizer.Create(
            true,
            "alice:second@proxy.example:8080",
            string.Empty,
            true,
            "https://config.example/proxy.pac?token=second",
            false,
            true);

        first.ProxyServer.Should().Be(second.ProxyServer);
        first.AutoConfigUrl.Should().Be(second.AutoConfigUrl);
        first.Fingerprint.Should().NotBe(second.Fingerprint);

        var before = new ProxyBaselineSnapshot([new ProxyStateEntry(ProxyStateScope.WinHttpMachine, "machine", first)]);
        var after = new ProxyBaselineSnapshot([new ProxyStateEntry(ProxyStateScope.WinHttpMachine, "machine", second)]);
        ProxyBaselineSnapshotter.Diff(before, after).Should().ContainSingle();
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-1001", true)]
    [InlineData("S-1-5-18", true)]
    [InlineData("S-1-5-21-1-2-3-1001_Classes", false)]
    [InlineData(".DEFAULT", false)]
    [InlineData("not-a-sid", false)]
    public void Loaded_profile_filter_accepts_only_real_sid_keys(string value, bool expected)
    {
        WindowsProxyStateSource.IsUserSid(value).Should().Be(expected);
    }

    [Fact]
    public void Invalid_or_non_json_netsh_output_is_rejected()
    {
        ProxyStateNormalizer.TryParseWinHttpAdvancedJson("command not supported", out var settings).Should().BeFalse();
        settings.Available.Should().BeFalse();
    }

    [Fact]
    public void Live_snapshot_captures_machine_and_current_user_without_throwing()
    {
        var snapshot = new ProxyBaselineSnapshotter().Capture();

        snapshot.Entries.Should().Contain(e => e.Scope == ProxyStateScope.WinHttpMachine && e.Identity == "machine");
        snapshot.Entries.Should().Contain(e => e.Scope == ProxyStateScope.WinInetUser);
        snapshot.Entries.Should().OnlyContain(e =>
            e.Settings.Fingerprint.Length == 0 || e.Settings.Fingerprint.Length == 64);
    }

    private static ProxyStateEntry Entry(ProxyStateScope scope, string identity, bool enabled, string server)
        => new(scope, identity, ProxyStateNormalizer.Create(
            enabled,
            server,
            string.Empty,
            autoConfigEnabled: false,
            autoConfigUrl: string.Empty,
            autoDetect: false,
            perUserProxySettings: scope == ProxyStateScope.WinInetUser));

    private sealed class FakeSource(
        IReadOnlyList<ProxyStateEntry> users,
        ProxyStateEntry machine) : IProxyStateSource
    {
        public IReadOnlyList<ProxyStateEntry> CaptureWinInetUsers() => users;
        public ProxyStateEntry CaptureWinHttpMachine() => machine;
    }
}
