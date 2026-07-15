namespace HostsGuard.Core;

/// <summary>
/// Deterministic ranking for review-only allowlist candidates. A recommendation
/// is eligible only when a blocked domain is repeatedly observed, resolves
/// through known CDN infrastructure, and its direct parent application matches
/// an explicit trusted-folder or trusted-publisher decision.
/// </summary>
public static class AllowlistRecommendationScorer
{
    public const long MinimumHits = 5;

    public static int Score(long hits, bool resolvesToCdn, bool parentTrusted)
    {
        if (hits < MinimumHits || !resolvesToCdn || !parentTrusted)
        {
            return 0;
        }

        return 70 + FrequencyPoints(hits);
    }

    private static int FrequencyPoints(long hits) => hits switch
    {
        >= 1_000 => 30,
        >= 250 => 25,
        >= 100 => 20,
        >= 25 => 15,
        >= 10 => 10,
        _ => 5,
    };
}
