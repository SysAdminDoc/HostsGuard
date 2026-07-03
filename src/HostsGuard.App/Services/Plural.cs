namespace HostsGuard.App.Services;

/// <summary>
/// Count formatting that respects the singular, so status lines read
/// "1 domain" / "2 domains" instead of "1 domains". Uses the invariant "s"
/// plural unless an explicit plural is given.
/// </summary>
public static class Plural
{
    /// <summary>e.g. <c>Of(1, "domain")</c> → "1 domain"; <c>Of(3, "domain")</c> → "3 domains".</summary>
    public static string Of(int count, string singular, string? plural = null)
        => count == 1 ? $"1 {singular}" : $"{count} {plural ?? singular + "s"}";
}
