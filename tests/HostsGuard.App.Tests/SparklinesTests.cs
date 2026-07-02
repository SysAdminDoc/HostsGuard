using System.Globalization;
using FluentAssertions;
using HostsGuard.App.Services;
using Xunit;

namespace HostsGuard.App.Tests;

/// <summary>NET-042: histogram → Polyline points geometry stays on the canvas.</summary>
public sealed class SparklinesTests
{
    private static (double X, double Y)[] Parse(string points) => points
        .Split(' ', StringSplitOptions.RemoveEmptyEntries)
        .Select(p => p.Split(','))
        .Select(xy => (double.Parse(xy[0], CultureInfo.InvariantCulture), double.Parse(xy[1], CultureInfo.InvariantCulture)))
        .ToArray();

    [Fact]
    public void Empty_or_null_series_render_nothing()
    {
        Sparklines.BuildPoints(Array.Empty<int>()).Should().BeEmpty();
        Sparklines.BuildPoints(null!).Should().BeEmpty();
    }

    [Fact]
    public void Points_span_the_width_and_stay_within_the_canvas()
    {
        var hits = new[] { 0, 2, 5, 1, 8, 0, 3, 4 };

        var pts = Parse(Sparklines.BuildPoints(hits));

        pts.Should().HaveCount(hits.Length);
        pts.Should().OnlyContain(p => p.X >= 0 && p.X <= Sparklines.Width && p.Y >= 0 && p.Y <= Sparklines.Height);
        pts[0].X.Should().Be(0);
        pts[^1].X.Should().BeApproximately(Sparklines.Width, 0.01);
    }

    [Fact]
    public void Peak_hour_maps_to_the_top_and_zero_to_the_baseline()
    {
        var hits = new[] { 0, 10, 0 };

        var pts = Parse(Sparklines.BuildPoints(hits));

        pts[1].Y.Should().BeLessThan(pts[0].Y); // peak is higher (smaller Y) than zero
        pts[0].Y.Should().BeApproximately(Sparklines.Height - 1, 0.01); // zero sits on the baseline
    }

    [Fact]
    public void Flat_series_is_a_level_line()
    {
        var pts = Parse(Sparklines.BuildPoints(new[] { 3, 3, 3, 3 }));
        pts.Select(p => p.Y).Distinct().Should().ContainSingle();
    }
}
