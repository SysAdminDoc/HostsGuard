namespace HostsGuard.Core;

/// <summary>
/// Local, offline heuristic for algorithmically-generated domains (DGA malware,
/// DNS-tunnel labels) — NET-201. It scores the REGISTRABLE label (eTLD+1's
/// second-level name), not subdomains, so a random CDN subdomain under a normal
/// root (<c>d1a2b3c4.cloudfront.net</c>) is ignored while a random registered
/// name (<c>kq3v9xzptlw.com</c>) is flagged. Deterministic and dependency-free;
/// tuned to favour false-negatives (it is a detector, not a blocker).
/// </summary>
public static class DgaHeuristic
{
    /// <summary>Below this label length the signal is too weak to classify.</summary>
    private const int MinLabelLength = 9;

    private const string Vowels = "aeiou";

    /// <summary>True when the domain's registrable label looks algorithmically generated.</summary>
    public static bool LooksAlgorithmic(string? domain)
    {
        var label = RegistrableLabel(domain);
        if (label.Length < MinLabelLength)
        {
            return false;
        }

        var letters = label.Count(char.IsLetter);
        var digits = label.Count(char.IsDigit);
        if (letters == 0)
        {
            return true; // all digits/hyphens in a registrable name is not a word
        }

        var entropy = ShannonEntropy(label);
        var vowelRatio = label.Count(c => Vowels.Contains(c, StringComparison.Ordinal)) / (double)Math.Max(1, letters);
        var digitRatio = digits / (double)label.Length;
        var maxConsonantRun = MaxConsonantRun(label);

        // High entropy is necessary; a genuine multi-word brand ("googletagmanager")
        // is long but low-entropy with normal vowel structure. Require the entropy
        // signal AND at least one structural anomaly a pronounceable name lacks.
        var highEntropy = entropy >= 3.2;
        var anomalous = vowelRatio < 0.25 || digitRatio >= 0.35 || maxConsonantRun >= 5;
        return highEntropy && anomalous;
    }

    /// <summary>The eTLD+1's second-level label, lowercased (e.g. "example" for a.example.co.uk-ish roots).</summary>
    private static string RegistrableLabel(string? domain)
    {
        var d = (domain ?? string.Empty).ToLowerInvariant().Trim().TrimEnd('.');
        if (d.Length == 0 || !Domains.LooksLikeDomain(d))
        {
            return string.Empty;
        }

        var root = Domains.GetRoot(d);
        var dot = root.IndexOf('.', StringComparison.Ordinal);
        return dot > 0 ? root[..dot] : root;
    }

    private static double ShannonEntropy(string s)
    {
        var counts = new Dictionary<char, int>();
        foreach (var c in s)
        {
            counts[c] = counts.GetValueOrDefault(c) + 1;
        }

        var len = s.Length;
        var entropy = 0.0;
        foreach (var n in counts.Values)
        {
            var p = n / (double)len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static int MaxConsonantRun(string label)
    {
        int max = 0, run = 0;
        foreach (var c in label)
        {
            if (char.IsLetter(c) && !Vowels.Contains(c, StringComparison.Ordinal))
            {
                run++;
                max = Math.Max(max, run);
            }
            else
            {
                run = 0;
            }
        }

        return max;
    }
}
