using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>NET-063: canonical action → category mapping for grouped metrics.</summary>
public sealed class EventTaxonomyTests
{
    [Theory]
    [InlineData(EventTaxonomy.ConsentAllow, EventTaxonomy.Categories.Consent)]
    [InlineData(EventTaxonomy.ConsentTimeout, EventTaxonomy.Categories.Consent)]
    [InlineData(EventTaxonomy.ModeChanged, EventTaxonomy.Categories.Consent)]
    [InlineData(EventTaxonomy.PostureRestoredOnStop, EventTaxonomy.Categories.Consent)]
    [InlineData(EventTaxonomy.FwBlocked, EventTaxonomy.Categories.Firewall)]
    [InlineData(EventTaxonomy.LockdownOn, EventTaxonomy.Categories.Firewall)]
    [InlineData(EventTaxonomy.EnforcementPaused, EventTaxonomy.Categories.Policy)]
    [InlineData(EventTaxonomy.EnforcementResumed, EventTaxonomy.Categories.Policy)]
    [InlineData(EventTaxonomy.Blocked, EventTaxonomy.Categories.Hosts)]
    [InlineData(EventTaxonomy.BackupRestored, EventTaxonomy.Categories.Hosts)]
    [InlineData(EventTaxonomy.ExclusionAdded, EventTaxonomy.Categories.Defender)]
    [InlineData(EventTaxonomy.BundleExport, EventTaxonomy.Categories.Support)]
    [InlineData("doh_refreshed", EventTaxonomy.Categories.Dns)]
    [InlineData("blocklist_imported", EventTaxonomy.Categories.Lists)]
    public void Categorizes_known_actions(string action, string expected)
        => EventTaxonomy.Category(action).Should().Be(expected);

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("something_unmapped")]
    public void Unknown_actions_fall_back_to_other(string? action)
        => EventTaxonomy.Category(action).Should().Be(EventTaxonomy.Categories.Other);

    [Fact]
    public void Category_is_case_insensitive()
        => EventTaxonomy.Category("FW_BLOCKED").Should().Be(EventTaxonomy.Categories.Firewall);
}
