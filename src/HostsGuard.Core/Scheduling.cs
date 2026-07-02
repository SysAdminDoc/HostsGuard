namespace HostsGuard.Core;

/// <summary>
/// Time-window logic for scheduled blocking. Port of Python <c>_in_window</c>,
/// including overnight (end &lt;= start) windows. Times are "HH:mm" strings compared
/// lexicographically, which is order-preserving for zero-padded 24h time.
/// </summary>
public static class Scheduling
{
    public static readonly IReadOnlyList<string> Weekdays = new[] { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };

    /// <summary>True if <paramref name="nowHhmm"/> falls in the half-open window [start, end).</summary>
    public static bool InWindow(string nowHhmm, string start, string end)
    {
        ArgumentNullException.ThrowIfNull(nowHhmm);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(end);

        if (start == end)
        {
            return false;
        }

        if (string.CompareOrdinal(start, end) < 0)
        {
            return string.CompareOrdinal(start, nowHhmm) <= 0 && string.CompareOrdinal(nowHhmm, end) < 0;
        }

        // Overnight window (crosses midnight).
        return string.CompareOrdinal(nowHhmm, start) >= 0 || string.CompareOrdinal(nowHhmm, end) < 0;
    }
}
