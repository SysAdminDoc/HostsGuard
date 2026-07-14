using System;
using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class BoundedDedupSetTests
{
    private static readonly DateTime T0 = new(2026, 7, 14, 0, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Add_is_fire_once_within_the_window()
    {
        var set = new BoundedDedupSet();
        set.Add("example.com", T0).Should().BeTrue();
        set.Add("example.com", T0.AddMinutes(5)).Should().BeFalse();
        set.Add("other.com", T0).Should().BeTrue();
    }

    [Fact]
    public void Add_refires_after_the_ttl_expires()
    {
        var set = new BoundedDedupSet(ttl: TimeSpan.FromHours(1));
        set.Add("example.com", T0).Should().BeTrue();
        set.Add("example.com", T0.AddMinutes(30)).Should().BeFalse();
        // Past the TTL the key is a fresh occurrence again (and memory is reclaimed).
        set.Add("example.com", T0.AddHours(2)).Should().BeTrue();
    }

    [Fact]
    public void Set_stays_bounded_across_a_flood_of_distinct_keys()
    {
        // The exact leak the item targets: one entry per distinct domain forever.
        var set = new BoundedDedupSet(capacity: 100, ttl: TimeSpan.FromHours(24));
        for (var i = 0; i < 10_000; i++)
        {
            set.Add($"domain-{i}.example", T0.AddSeconds(i)).Should().BeTrue();
        }

        set.Count.Should().BeLessThanOrEqualTo(100);
    }

    [Fact]
    public void Duplicate_hits_refresh_recency_so_active_keys_survive_eviction()
    {
        var set = new BoundedDedupSet(capacity: 4, ttl: TimeSpan.FromDays(30));
        set.Add("hot", T0).Should().BeTrue();

        // Fill past capacity with cold keys, keeping "hot" active as we go.
        for (var i = 0; i < 50; i++)
        {
            var now = T0.AddSeconds(i + 1);
            set.Add($"cold-{i}", now);
            set.Add("hot", now); // refreshes recency; still a duplicate
        }

        set.Count.Should().BeLessThanOrEqualTo(4);
        // "hot" was continuously refreshed, so it is never the oldest — still deduped.
        set.Add("hot", T0.AddMinutes(2)).Should().BeFalse();
    }

    [Fact]
    public void Comparer_controls_case_sensitivity()
    {
        var ordinal = new BoundedDedupSet(comparer: StringComparer.Ordinal);
        ordinal.Add("App.EXE", T0).Should().BeTrue();
        ordinal.Add("app.exe", T0).Should().BeTrue(); // distinct under Ordinal

        var ignoreCase = new BoundedDedupSet(comparer: StringComparer.OrdinalIgnoreCase);
        ignoreCase.Add("App.EXE", T0).Should().BeTrue();
        ignoreCase.Add("app.exe", T0).Should().BeFalse(); // same under OrdinalIgnoreCase
    }

    [Fact]
    public void Add_rejects_null_key()
    {
        var set = new BoundedDedupSet();
        Action act = () => set.Add(null!, T0);
        act.Should().Throw<ArgumentNullException>();
    }
}
