namespace HostsGuard.Core;

public sealed record DgaScoreBreakdown(
    string Version,
    string Domain,
    string RegistrableLabel,
    int LabelLength,
    int MinimumLabelLength,
    bool IsValidDomain,
    bool IsIdnEncoded,
    int LetterCount,
    int DigitCount,
    double Entropy,
    double EntropyThreshold,
    double EntropyWeight,
    double EntropyContribution,
    double VowelRatio,
    double VowelRatioThreshold,
    double LowVowelWeight,
    double LowVowelContribution,
    double DigitRatio,
    double DigitRatioThreshold,
    double HighDigitWeight,
    double HighDigitContribution,
    int MaxConsonantRun,
    int ConsonantRunThreshold,
    double ConsonantRunWeight,
    double ConsonantRunContribution,
    double NumericOnlyWeight,
    double NumericOnlyContribution,
    double Score,
    double DecisionThreshold,
    bool IsAlgorithmic,
    string Reason);

/// <summary>
/// Local, deterministic, alert-only heuristic for algorithmically generated
/// registrable labels. It never blocks and is disabled by default at the service layer.
/// </summary>
public static class DgaHeuristic
{
    public const string ScoreVersion = "dga-score-v1";
    public const int MinimumLabelLength = 9;
    public const double EntropyThreshold = 3.2;
    public const double VowelRatioThreshold = 0.25;
    public const double DigitRatioThreshold = 0.35;
    public const int ConsonantRunThreshold = 5;
    public const double EntropyWeight = 1.0;
    public const double LowVowelWeight = 1.0;
    public const double HighDigitWeight = 1.0;
    public const double ConsonantRunWeight = 1.0;
    public const double NumericOnlyWeight = 2.0;
    public const double DecisionThreshold = 2.0;

    private const string Vowels = "aeiou";

    public static bool LooksAlgorithmic(string? domain) => Analyze(domain).IsAlgorithmic;

    public static DgaScoreBreakdown Analyze(string? domain)
    {
        var input = (domain ?? string.Empty).Trim().TrimEnd('.');
        var label = RegistrableLabel(input, out var valid, out var idn);
        var letters = label.Count(char.IsLetter);
        var digits = label.Count(char.IsDigit);
        var entropy = label.Length == 0 ? 0 : ShannonEntropy(label);
        var vowelRatio = label.Count(c => Vowels.Contains(c, StringComparison.Ordinal)) / (double)Math.Max(1, letters);
        var digitRatio = digits / (double)Math.Max(1, label.Length);
        var run = MaxConsonantRun(label);

        var entropyContribution = entropy >= EntropyThreshold ? EntropyWeight : 0;
        var lowVowelContribution = letters > 0 && vowelRatio < VowelRatioThreshold ? LowVowelWeight : 0;
        var digitContribution = digitRatio >= DigitRatioThreshold ? HighDigitWeight : 0;
        var runContribution = run >= ConsonantRunThreshold ? ConsonantRunWeight : 0;
        var numericContribution = letters == 0 && label.Length >= MinimumLabelLength ? NumericOnlyWeight : 0;
        var score = entropyContribution + lowVowelContribution + digitContribution + runContribution + numericContribution;

        string reason;
        bool algorithmic;
        if (!valid)
        {
            reason = "invalid_domain";
            algorithmic = false;
        }
        else if (idn)
        {
            reason = "idn_encoding_excluded";
            algorithmic = false;
        }
        else if (label.Length < MinimumLabelLength)
        {
            reason = "label_too_short";
            algorithmic = false;
        }
        else if (numericContribution > 0)
        {
            reason = "numeric_only";
            algorithmic = true;
        }
        else
        {
            var structural = lowVowelContribution + digitContribution + runContribution > 0;
            algorithmic = entropyContribution > 0 && structural && score >= DecisionThreshold;
            reason = algorithmic ? "entropy_and_structure" : entropyContribution == 0 ? "entropy_below_threshold" : "structure_normal";
        }

        return new(ScoreVersion, input, label, label.Length, MinimumLabelLength, valid, idn,
            letters, digits, entropy, EntropyThreshold, EntropyWeight, entropyContribution,
            vowelRatio, VowelRatioThreshold, LowVowelWeight, lowVowelContribution,
            digitRatio, DigitRatioThreshold, HighDigitWeight, digitContribution,
            run, ConsonantRunThreshold, ConsonantRunWeight, runContribution,
            NumericOnlyWeight, numericContribution, score, DecisionThreshold, algorithmic, reason);
    }

    private static string RegistrableLabel(string domain, out bool valid, out bool idn)
    {
        var ascii = Domains.ToAscii(domain);
        valid = Domains.LooksLikeDomain(ascii);
        if (!valid)
        {
            idn = false;
            return string.Empty;
        }

        var root = Domains.GetRoot(ascii);
        var dot = root.IndexOf('.', StringComparison.Ordinal);
        var label = dot > 0 ? root[..dot] : root;
        idn = label.StartsWith("xn--", StringComparison.OrdinalIgnoreCase);
        return label.ToLowerInvariant();
    }

    private static double ShannonEntropy(string s)
    {
        var counts = new Dictionary<char, int>();
        foreach (var c in s) counts[c] = counts.GetValueOrDefault(c) + 1;
        var entropy = 0.0;
        foreach (var n in counts.Values)
        {
            var p = n / (double)s.Length;
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
                max = Math.Max(max, ++run);
            }
            else
            {
                run = 0;
            }
        }
        return max;
    }
}
