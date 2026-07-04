namespace HostsGuard.Core;

/// <summary>
/// Extracts the human publisher name (the certificate CN) from an Authenticode
/// signer subject so a firewall/consent rule can trust "everything signed by X"
/// (NET-113) rather than a single binary. Pure — no OS deps.
/// </summary>
public static class PublisherName
{
    /// <summary>
    /// The CN value from an X.500 subject like
    /// <c>CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, ...</c>,
    /// or the trimmed subject when no CN is present; "" for null/empty input.
    /// </summary>
    public static string Of(string? signerSubject)
    {
        var subject = (signerSubject ?? string.Empty).Trim();
        if (subject.Length == 0)
        {
            return string.Empty;
        }

        // Split on commas that separate RDNs; a CN can itself contain commas only
        // when quoted/escaped, which is rare for publisher names — take the CN=
        // token's value up to the next unescaped comma.
        foreach (var part in SplitRdns(subject))
        {
            var t = part.Trim();
            if (t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return t[3..].Trim().Trim('"');
            }
        }

        return subject;
    }

    /// <summary>True when two signer subjects share the same publisher (CN), case-insensitively.</summary>
    public static bool SamePublisher(string? a, string? b)
    {
        var pa = Of(a);
        var pb = Of(b);
        return pa.Length != 0 && string.Equals(pa, pb, StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> SplitRdns(string subject)
    {
        var start = 0;
        for (var i = 0; i < subject.Length; i++)
        {
            if (subject[i] == ',' && (i == 0 || subject[i - 1] != '\\'))
            {
                yield return subject[start..i];
                start = i + 1;
            }
        }

        yield return subject[start..];
    }
}
