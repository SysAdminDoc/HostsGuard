using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Windows;
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-107 in-app AI-knowledge review: list learned entries, promote them into a
/// persisted user-override store that beats the AI in the feed, correct a domain
/// directly, discard wrong guesses, and filter to what's new since the last review.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AiKnowledgeReviewTests : IAsyncLifetime
{
    private string _dir = null!;
    private WebApplication _app = null!;
    private ServiceState _state = null!;
    private string _token = null!;
    private string _pipe = null!;

    // A domain with no curated purpose/category, so learned/override is what shows.
    private const string Domain = "weirdtracker123.example.net";

    public async Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_kn_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _state = new ServiceState(new HostsEngine(hostsPath), new HostsDatabase(Path.Combine(_dir, "hostsguard.db")), dataDir: _dir);
        _token = SessionToken.Generate();
        _pipe = "HostsGuard.KnTest." + Guid.NewGuid().ToString("N");
        _app = ServiceHost.Build(_state, _token, _pipe);
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _app.DisposeAsync();
        _state.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task Promoted_and_corrected_labels_beat_the_ai_in_the_feed()
    {
        _state.RecordDns(Domain);
        _state.Db.UpsertAiKnowledge("purpose", Domain, "AI guessed purpose", "test-model");

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);

        // Baseline: the feed shows the AI-learned purpose.
        var before = await hosts.GetActivityAsync(new ActivityRequest());
        before.Rows.Single(r => r.Domain == Domain).Purpose.Should().Be("AI guessed purpose");

        // Correct it — the override must beat the AI and be remembered.
        var ack = await hosts.OverrideKnowledgeAsync(new KnowledgeOverrideRequest
        {
            Kind = "purpose", Key = Domain, Value = "User-known: analytics beacon",
        });
        ack.Ok.Should().BeTrue();

        var after = await hosts.GetActivityAsync(new ActivityRequest());
        after.Rows.Single(r => r.Domain == Domain).Purpose.Should().Be("User-known: analytics beacon");
        _state.Db.GetUserOverride("purpose", Domain).Should().Be("User-known: analytics beacon");
    }

    [Fact]
    public async Task List_promote_and_discard_round_trip()
    {
        _state.Db.UpsertAiKnowledge("category", Domain, "Tracking & Analytics", "test-model");
        _state.Db.UpsertAiKnowledge("purpose", "bad.example.net", "wrong guess", "test-model");

        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var hosts = new HostsControl.HostsControlClient(channel);

        var list = await hosts.ListAiKnowledgeAsync(new AiKnowledgeRequest());
        list.Entries.Should().Contain(e => e.Key == Domain && e.Kind == "category");
        list.Entries.Should().OnlyContain(e => e.IsNew); // never reviewed => all new

        // Promote the category entry into a user override (edited value).
        var promote = new KnowledgeReviewRequest();
        promote.Actions.Add(new KnowledgeReviewAction { Kind = "category", Key = Domain, Action = "promote", Value = "Advertising" });
        // Discard the wrong purpose guess.
        promote.Actions.Add(new KnowledgeReviewAction { Kind = "purpose", Key = "bad.example.net", Action = "discard" });
        promote.MarkReviewed = true;
        (await hosts.PromoteKnowledgeAsync(promote)).Ok.Should().BeTrue();

        _state.Db.GetUserOverride("category", Domain).Should().Be("Advertising");
        _state.Db.GetAiKnowledge("purpose", new[] { "bad.example.net" }).Should().NotContainKey("bad.example.net");

        // After marking reviewed, nothing is "new".
        var afterReview = await hosts.ListAiKnowledgeAsync(new AiKnowledgeRequest { SinceLastReview = true });
        afterReview.Entries.Should().BeEmpty();
        afterReview.LastReviewed.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Override_rejects_unknown_kind()
    {
        using var channel = NamedPipeChannel.Create(_token, _pipe);
        var ack = await new HostsControl.HostsControlClient(channel).OverrideKnowledgeAsync(
            new KnowledgeOverrideRequest { Kind = "bogus", Key = Domain, Value = "x" });
        ack.Ok.Should().BeFalse();
        ack.ErrorCode.Should().Be("hostsguard.error.v1/invalid_override");
    }
}
