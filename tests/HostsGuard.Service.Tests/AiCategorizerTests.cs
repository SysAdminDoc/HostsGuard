using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

internal sealed class FakeAiCompleter : IAiCompleter
{
    public string Reply { get; set; } = "{}";

    public List<string> Prompts { get; } = new();

    public Task<string> CompleteAsync(AiSettings settings, string systemPrompt, string userPrompt, CancellationToken ct)
    {
        Prompts.Add(userPrompt);
        return Task.FromResult(Reply);
    }
}

[SupportedOSPlatform("windows")]
public sealed class AiCategorizerTests : IDisposable
{
    private readonly string _dir;
    private readonly string _hostsPath;
    private readonly HostsDatabase _db;
    private readonly HostsEngine _hosts;
    private readonly FakeAiCompleter _completer = new();
    private readonly AiCategorizer _ai;

    public AiCategorizerTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_ai_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(_hostsPath, "# hosts\n");
        _db = new HostsDatabase(Path.Combine(_dir, "db.sqlite"));
        _hosts = new HostsEngine(_hostsPath);
        _ai = new AiCategorizer(_db, _hosts, _completer, _dir);
    }

    public void Dispose()
    {
        _db.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public void Settings_round_trip_and_blank_key_keeps_the_stored_one()
    {
        _ai.SaveSettings("sk-test-123", "", "", enabled: true);
        _ai.Settings.Should().Be(new AiSettings("sk-test-123", "deepseek-chat", "https://api.deepseek.com", true));

        _ai.SaveSettings("", "deepseek-reasoner", "", enabled: false);
        _ai.Settings.ApiKey.Should().Be("sk-test-123");
        _ai.Settings.Model.Should().Be("deepseek-reasoner");
        _ai.Settings.Enabled.Should().BeFalse();
    }

    [Fact]
    public async Task Categorize_persists_categories_and_organizes_the_hosts_file()
    {
        _hosts.Block("pagead2.googlesyndication.com");
        _hosts.Block("telemetry.microsoft.com");
        _db.AddDomain("pagead2.googlesyndication.com");
        _db.AddDomain("telemetry.microsoft.com");
        _ai.SaveSettings("sk-test", "", "", enabled: true);
        _completer.Reply = """
            {"pagead2.googlesyndication.com": "Google Ads", "telemetry.microsoft.com": "Microsoft Telemetry"}
            """;

        var results = await _ai.CategorizeAsync(
            new[] { "pagead2.googlesyndication.com", "telemetry.microsoft.com" }, CancellationToken.None);

        results.Should().HaveCount(2);
        // Both are curated, so they resolve offline to canonical categories
        // (the AI reply is never consulted).
        _db.GetDomains().Single(d => d.Domain == "pagead2.googlesyndication.com").Category.Should().Be("Advertising");
        var text = File.ReadAllText(_hostsPath);
        text.Should().Contain("# Advertising").And.Contain("# Telemetry");
        text.IndexOf("# Advertising", StringComparison.Ordinal)
            .Should().BeLessThan(text.IndexOf("0.0.0.0 pagead2.googlesyndication.com", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Categorize_without_a_key_throws_a_clear_error()
    {
        var act = () => _ai.CategorizeAsync(new[] { "a.example.com" }, CancellationToken.None);
        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*API key*");
    }

    [Fact]
    public async Task Curated_categories_apply_without_any_api_key()
    {
        _hosts.Block("pixel.facebook.com");
        _db.AddDomain("pixel.facebook.com");

        var results = await _ai.CategorizeAsync(new[] { "pixel.facebook.com" }, CancellationToken.None);

        results.Should().ContainSingle().Which.Should().Be(("pixel.facebook.com", "Tracking & Analytics"));
        _completer.Prompts.Should().BeEmpty("the curated table answered — no AI call needed");
        File.ReadAllText(_hostsPath).Should().Contain("# Tracking & Analytics");
    }

    [Fact]
    public async Task Only_domains_the_curated_table_misses_go_to_the_ai()
    {
        _db.AddDomain("secure.adnxs.com");
        _db.AddDomain("weird.example.net");
        _ai.SaveSettings("sk-test", "", "", enabled: true);
        _completer.Reply = """{"weird.example.net": "Other"}""";

        var results = await _ai.CategorizeAsync(
            new[] { "secure.adnxs.com", "weird.example.net" }, CancellationToken.None);

        results.Should().HaveCount(2);
        _completer.Prompts.Single().Should().Contain("weird.example.net").And.NotContain("adnxs");
    }

    [Fact]
    public async Task ResearchPurposes_stores_knowledge_and_skips_unknown()
    {
        _ai.SaveSettings("sk-test", "", "", enabled: true);
        _completer.Reply = """
            {"ads.example.com": "Google display ads serving", "mystery.example.net": "Unknown"}
            """;

        var results = await _ai.ResearchPurposesAsync(
            new[] { "ads.example.com", "mystery.example.net" }, CancellationToken.None);

        results.Should().ContainSingle().Which.Should().Be(("ads.example.com", "Google display ads serving"));
        _db.GetAiKnowledge("purpose", new[] { "ads.example.com" })
            .Should().ContainKey("ads.example.com").WhoseValue.Should().Be("Google display ads serving");
        _db.GetAiKnowledge("purpose", new[] { "mystery.example.net" }).Should().BeEmpty();
    }

    [Fact]
    public async Task IdentifyConnections_keys_by_host_or_ip_and_records_knowledge()
    {
        _ai.SaveSettings("sk-test", "", "", enabled: true);
        _completer.Reply = """
            {"steamcdn.example.com": "Steam downloading game content", "203.0.113.9": "Windows Update delivery"}
            """;

        var results = await _ai.IdentifyConnectionsAsync(new[]
        {
            ("198.51.100.7", "steamcdn.example.com", "steam", 443),
            ("203.0.113.9", "", "svchost", 80),
        }, CancellationToken.None);

        results.Should().HaveCount(2);
        _db.GetAiKnowledge("connection", new[] { "steamcdn.example.com", "203.0.113.9" }).Should().HaveCount(2);
        _completer.Prompts.Single().Should().Contain("process=steam").And.Contain("ip=203.0.113.9");
    }

    [Fact]
    public async Task CategorizeHostsFile_adopts_unmanaged_entries_and_reuses_existing_sections()
    {
        File.WriteAllText(_hostsPath, "# Google Ads\n0.0.0.0 ad.doubleclick.net\n0.0.0.0 orphan.example.com\n");
        var hosts = new HostsEngine(_hostsPath);
        var ai = new AiCategorizer(_db, hosts, _completer, _dir);
        ai.SaveSettings("sk-test", "", "", enabled: true);
        _completer.Reply = """
            {"ad.doubleclick.net": "Google Ads", "orphan.example.com": "Major Trackers"}
            """;

        var results = await ai.CategorizeHostsFileAsync(CancellationToken.None);

        results.Should().HaveCount(2);
        // The prompt offered the file's existing section names as vocabulary,
        // and the curated hit (doubleclick) never went to the AI at all.
        _completer.Prompts.Single().Should().Contain("Google Ads").And.NotContain("doubleclick");
        _db.GetDomains().Single(d => d.Domain == "ad.doubleclick.net").Category.Should().Be("Advertising");
        // The unmanaged AI-categorized entry is folded into the canonical taxonomy
        // ("Major Trackers" -> "Tracking & Analytics").
        _db.GetDomains().Single(d => d.Domain == "orphan.example.com").Category.Should().Be("Tracking & Analytics");
        // Knowledge log captured only the AI-learned category for later review.
        _db.GetAiKnowledge("category", new[] { "ad.doubleclick.net", "orphan.example.com" })
            .Should().ContainSingle().Which.Key.Should().Be("orphan.example.com");
        File.ReadAllText(_hostsPath).Should().Contain("# Tracking & Analytics");
    }

    [Fact]
    public async Task DeepSeek_completer_refuses_a_non_https_endpoint_before_sending_the_key()
    {
        using var completer = new DeepSeekCompleter();
        var settings = new AiSettings("sk-secret", "deepseek-chat", "http://insecure.example.com", true);

        // Must throw on the scheme check, before the API key ever hits the wire.
        var act = () => completer.CompleteAsync(settings, "sys", "user", CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*https*");
    }

    [Fact]
    public void ParseReply_keeps_only_requested_domains_with_sane_categories()
    {
        var requested = new[] { "a.example.com", "b.example.com" };
        var parsed = AiCategorizer.ParseReply(
            """
            {"a.example.com": "Ads", "b.example.com": 42,
             "evil-injected.com": "Malware", "A.EXAMPLE.COM": ""}
            """, requested);

        parsed.Should().ContainSingle().Which.Should().Be(("a.example.com", "Ads"));
        AiCategorizer.ParseReply("not json at all", requested).Should().BeEmpty();
        AiCategorizer.ParseReply("[1,2]", requested).Should().BeEmpty();
    }
}
