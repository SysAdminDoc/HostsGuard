using System.Globalization;

namespace HostsGuard.App.Services;

/// <summary>Compact, human display form for the ISO timestamps the service emits.</summary>
public static class TimeText
{
    /// <summary>
    /// "14:32:07" for today, "Mar 5, 14:32" for this year, "2025-03-05 14:32"
    /// otherwise. Unparseable input passes through unchanged.
    /// </summary>
    public static string Compact(string iso)
    {
        if (!DateTime.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var ts))
        {
            return iso;
        }

        var local = ts.Kind == DateTimeKind.Utc ? ts.ToLocalTime() : ts;
        var now = DateTime.Now;
        if (local.Date == now.Date)
        {
            return local.ToString("HH:mm:ss", CultureInfo.CurrentCulture);
        }

        return local.Year == now.Year
            ? local.ToString("MMM d, HH:mm", CultureInfo.CurrentCulture)
            : local.ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture);
    }
}
