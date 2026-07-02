using System.Globalization;
using System.Text;

namespace HostsGuard.App.Services;

/// <summary>
/// Turns an hourly hit histogram into a Polyline points string on a fixed
/// canvas (NET-042). Pure and headless-testable; the view renders the string
/// through <see cref="PointsTextConverter"/> on a Viewbox-scaled canvas.
/// </summary>
public static class Sparklines
{
    public const double Width = 120;
    public const double Height = 20;

    /// <summary>
    /// "x,y x,y …" across the histogram, scaled to the canvas. A flat/empty
    /// series renders as a baseline. Peak maps to the top with a 1px margin.
    /// </summary>
    public static string BuildPoints(IReadOnlyList<int> hits, double width = Width, double height = Height)
    {
        if (hits is null || hits.Count == 0)
        {
            return string.Empty;
        }

        var peak = Math.Max(1, hits.Max());
        var stepX = hits.Count > 1 ? width / (hits.Count - 1) : 0;
        var sb = new StringBuilder(hits.Count * 8);
        for (var i = 0; i < hits.Count; i++)
        {
            var x = i * stepX;
            var y = height - (hits[i] / (double)peak * (height - 2)) - 1;
            if (i != 0)
            {
                sb.Append(' ');
            }

            sb.Append(x.ToString("0.#", CultureInfo.InvariantCulture))
              .Append(',')
              .Append(y.ToString("0.#", CultureInfo.InvariantCulture));
        }

        return sb.ToString();
    }
}
