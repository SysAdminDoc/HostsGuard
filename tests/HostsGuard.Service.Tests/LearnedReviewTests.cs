using System.Runtime.Versioning;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-074 "decide later": listing Learning-mode auto-decisions and the
/// promote / block / discard review verdicts.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LearnedReviewTests : IDisposable
{
    private readonly string _dir;
    private readonly HostsDatabase _db;
    private readonly FakeFirewallEngine _fw = new();
    private readonly ConsentBroker _broker;

    public LearnedReviewTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_learn_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _db = new HostsDatabase(Path.Combine(_dir, "hostsguard.db"));
        _broker = new ConsentBroker(_db, new EventBus(), _fw, null, _dir);
    }

    public void Dispose()
    {
        _broker.Dispose();
        _db.Dispose();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    private void Learn(string app)
    {
        _broker.SetMode(ConsentBroker.ModeLearning);
        _broker.OnBlocked(new BlockedConnection(DateTime.UtcNow, app, "Out", "1.2.3.4", 443, "TCP", 100, 5157));
    }

    [Fact]
    public void Learned_rules_are_listed_for_review()
    {
        Learn(@"C:\apps\one.exe");
        Learn(@"C:\apps\two.exe");

        var list = _broker.ListLearned();

        list.Entries.Should().HaveCount(2);
        list.Entries.Select(e => e.Application).Should().Contain([@"C:\apps\one.exe", @"C:\apps\two.exe"]);
        list.Entries.Should().OnlyContain(e => e.RuleName.StartsWith("HG_Learn_"));
    }

    [Fact]
    public void Promote_converts_the_auto_allow_into_a_permanent_consent_rule()
    {
        Learn(@"C:\apps\one.exe");
        var learned = _broker.ListLearned().Entries.Single();

        var ack = _broker.ReviewLearned(new LearnedReviewRequest
        {
            Actions = { new LearnedReviewAction { RuleName = learned.RuleName, Action = "promote" } },
        });

        ack.Ok.Should().BeTrue();
        ack.Message.Should().Contain("1 promoted");
        _fw.Rules.Should().ContainKey("HG_Consent_Allow_one_Out")
            .WhoseValue.Should().Match<Core.FwRule>(r => r.Action == "Allow" && r.Program == @"C:\apps\one.exe");
        _fw.Rules.Keys.Should().NotContain(learned.RuleName);
        _broker.ListLearned().Entries.Should().BeEmpty();
    }

    [Fact]
    public void Block_reverses_the_auto_allow_into_a_permanent_block()
    {
        Learn(@"C:\apps\one.exe");
        var learned = _broker.ListLearned().Entries.Single();

        _broker.ReviewLearned(new LearnedReviewRequest
        {
            Actions = { new LearnedReviewAction { RuleName = learned.RuleName, Action = "block" } },
        }).Ok.Should().BeTrue();

        _fw.Rules.Should().ContainKey("HG_Consent_Block_one_Out")
            .WhoseValue.Action.Should().Be("Block");
        _fw.Rules.Keys.Should().NotContain(learned.RuleName);
    }

    [Fact]
    public void Discard_removes_the_rule_so_the_app_prompts_again()
    {
        Learn(@"C:\apps\one.exe");
        var learned = _broker.ListLearned().Entries.Single();

        _broker.ReviewLearned(new LearnedReviewRequest
        {
            Actions = { new LearnedReviewAction { RuleName = learned.RuleName, Action = "discard" } },
        }).Message.Should().Contain("1 discarded");

        _fw.Rules.Should().BeEmpty();
    }

    [Fact]
    public void Unknown_rules_and_actions_are_skipped_not_fatal()
    {
        Learn(@"C:\apps\one.exe");
        var learned = _broker.ListLearned().Entries.Single();

        var ack = _broker.ReviewLearned(new LearnedReviewRequest
        {
            Actions =
            {
                new LearnedReviewAction { RuleName = "HG_Learn_ghost_Out", Action = "promote" },
                new LearnedReviewAction { RuleName = learned.RuleName, Action = "explode" },
            },
        });

        ack.Ok.Should().BeTrue();
        ack.Message.Should().Contain("2 skipped");
        _fw.Rules.Should().ContainKey(learned.RuleName); // untouched
    }
}
