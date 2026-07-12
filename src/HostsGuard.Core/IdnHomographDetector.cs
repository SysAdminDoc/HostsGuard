using System.Globalization;
using System.Reflection;
using System.Text;

namespace HostsGuard.Core;

public enum IdnDomainSource
{
    Allowlisted,
    Trusted,
    Recent,
}

public enum IdnRestrictionLevel
{
    Ascii,
    SingleScript,
    HighlyRestrictive,
    ModeratelyRestrictive,
    MinimallyRestrictive,
    Unrestricted,
}

public sealed record IdnHomographMatch(
    string Domain,
    IdnDomainSource Source,
    string Skeleton);

/// <summary>
/// Alert-only UTS #39-style assessment. A positive result is evidence for review,
/// never authority to block or mutate policy automatically.
/// </summary>
public sealed record IdnHomographAssessment(
    string Domain,
    string AsciiDomain,
    string UnicodeDomain,
    string Skeleton,
    bool IsIdn,
    bool IsSuspicious,
    IdnRestrictionLevel RestrictionLevel,
    IReadOnlyList<string> Scripts,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<IdnHomographMatch> Matches)
{
    public const string RecommendedAction = "alert_only";
}

/// <summary>
/// Pure IDNA + UTS #39-style confusable-skeleton detector. The restriction label
/// is conservative review evidence, not a claim of full UTS #39 conformance.
/// Unicode 17.0.0 data is embedded, so results do not depend on the host or network.
/// </summary>
public sealed class IdnHomographDetector
{
    public const string UnicodeVersion = "17.0.0";

    public static IdnHomographDetector Default { get; } = new();

    private readonly int _cacheCapacity;
    private readonly Dictionary<string, DomainFacts> _cache = new(StringComparer.Ordinal);
    private readonly object _cacheGate = new();

    private static readonly Lazy<UnicodeData> Data = new(LoadData, LazyThreadSafetyMode.ExecutionAndPublication);

    public IdnHomographDetector(int cacheCapacity = 2048)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(cacheCapacity, 16);
        _cacheCapacity = cacheCapacity;
    }

    /// <summary>Current bounded memoization footprint, exposed for diagnostics.</summary>
    public int CacheEntryCount
    {
        get { lock (_cacheGate) return _cache.Count; }
    }

    public IdnHomographAssessment Analyze(
        string domain,
        IEnumerable<string>? allowlistedDomains = null,
        IEnumerable<string>? trustedDomains = null,
        IEnumerable<string>? recentDomains = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        var candidate = Facts(domain);
        var matches = new List<IdnHomographMatch>();
        AddMatches(matches, candidate, allowlistedDomains, IdnDomainSource.Allowlisted);
        AddMatches(matches, candidate, trustedDomains, IdnDomainSource.Trusted);
        AddMatches(matches, candidate, recentDomains, IdnDomainSource.Recent);

        var orderedMatches = matches
            .DistinctBy(static match => (match.Source, match.Domain), MatchKeyComparer.Instance)
            .OrderBy(static match => match.Source)
            .ThenBy(static match => match.Domain, StringComparer.Ordinal)
            .ToArray();
        var evidence = new List<string>();
        if (candidate.Scripts.Count > 1) evidence.Add("mixed_script:" + string.Join('+', candidate.Scripts));
        if (candidate.HasConfusableMapping) evidence.Add("uts39_confusable_skeleton");
        if (orderedMatches.Length != 0) evidence.Add("skeleton_collision");
        evidence.Add("restriction_level:" + RestrictionToken(candidate.RestrictionLevel));

        return new(
            domain.Trim().TrimEnd('.'), candidate.Ascii, candidate.Unicode, candidate.Skeleton,
            candidate.IsIdn, candidate.IsIdn && orderedMatches.Length != 0, candidate.RestrictionLevel,
            candidate.Scripts, evidence, orderedMatches);
    }

    private void AddMatches(
        List<IdnHomographMatch> matches,
        DomainFacts candidate,
        IEnumerable<string>? references,
        IdnDomainSource source)
    {
        if (references is null) return;
        foreach (var referenceValue in references)
        {
            if (string.IsNullOrWhiteSpace(referenceValue)) continue;
            DomainFacts reference;
            try { reference = Facts(referenceValue); }
            catch (ArgumentException) { continue; }
            if (candidate.Ascii.Equals(reference.Ascii, StringComparison.Ordinal)) continue;
            if (!candidate.Skeleton.Equals(reference.Skeleton, StringComparison.Ordinal)) continue;
            matches.Add(new(reference.Ascii, source, reference.Skeleton));
        }
    }

    private DomainFacts Facts(string input)
    {
        var key = input.Trim().TrimEnd('.').ToLowerInvariant();
        if (key.Length == 0) throw new ArgumentException("Domain cannot be empty.", nameof(input));
        lock (_cacheGate)
        {
            if (_cache.TryGetValue(key, out var cached)) return cached;
        }

        var computed = ComputeFacts(key);
        lock (_cacheGate)
        {
            if (_cache.Count >= _cacheCapacity) _cache.Clear();
            _cache[key] = computed;
        }
        return computed;
    }

    private static DomainFacts ComputeFacts(string value)
    {
        var idn = new IdnMapping { AllowUnassigned = false, UseStd3AsciiRules = true };
        string ascii;
        string unicode;
        try
        {
            ascii = idn.GetAscii(value).ToLowerInvariant();
            unicode = idn.GetUnicode(ascii).Normalize(NormalizationForm.FormC).ToLowerInvariant();
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException("Domain is not valid IDNA input.", nameof(value), ex);
        }

        var rootAscii = Domains.GetRoot(ascii);
        var rootUnicode = idn.GetUnicode(rootAscii).Normalize(NormalizationForm.FormC).ToLowerInvariant();
        var mapped = false;
        var skeletonBuilder = new StringBuilder();
        foreach (var rune in rootUnicode.Normalize(NormalizationForm.FormD).EnumerateRunes())
        {
            if (Data.Value.Confusables.TryGetValue(rune.Value, out var replacement))
            {
                skeletonBuilder.Append(replacement);
                mapped |= !replacement.Equals(rune.ToString(), StringComparison.Ordinal);
            }
            else
            {
                skeletonBuilder.Append(rune.ToString());
            }
        }
        var skeleton = skeletonBuilder.ToString().Normalize(NormalizationForm.FormD).ToLowerInvariant();
        var scripts = ScriptsOf(rootUnicode);
        var restriction = RestrictionOf(rootUnicode, scripts);
        return new(ascii, unicode, skeleton, !ascii.Equals(unicode, StringComparison.Ordinal), scripts, restriction, mapped);
    }

    private static IReadOnlyList<string> ScriptsOf(string value) => value.EnumerateRunes()
        .Select(static rune => Data.Value.ScriptOf(rune.Value))
        .Where(static script => script is not "Common" and not "Inherited" and not "Unknown")
        .Distinct(StringComparer.Ordinal)
        .Order(StringComparer.Ordinal)
        .ToArray();

    private static IdnRestrictionLevel RestrictionOf(string value, IReadOnlyList<string> scripts)
    {
        if (value.All(static ch => ch <= 0x7F)) return IdnRestrictionLevel.Ascii;
        if (scripts.Count <= 1) return IdnRestrictionLevel.SingleScript;
        var set = scripts.ToHashSet(StringComparer.Ordinal);
        if (set.IsSubsetOf(new[] { "Latin", "Han", "Hiragana", "Katakana" }) ||
            set.IsSubsetOf(new[] { "Latin", "Han", "Bopomofo" }) ||
            set.IsSubsetOf(new[] { "Latin", "Han", "Hangul" }))
            return IdnRestrictionLevel.HighlyRestrictive;
        if (set.Count == 2 && set.Contains("Latin") && !set.Contains("Cyrillic") && !set.Contains("Greek"))
            return IdnRestrictionLevel.ModeratelyRestrictive;
        if (set.Count == 2) return IdnRestrictionLevel.MinimallyRestrictive;
        return IdnRestrictionLevel.Unrestricted;
    }

    private static string RestrictionToken(IdnRestrictionLevel level) => level switch
    {
        IdnRestrictionLevel.Ascii => "ascii",
        IdnRestrictionLevel.SingleScript => "single_script",
        IdnRestrictionLevel.HighlyRestrictive => "highly_restrictive",
        IdnRestrictionLevel.ModeratelyRestrictive => "moderately_restrictive",
        IdnRestrictionLevel.MinimallyRestrictive => "minimally_restrictive",
        _ => "unrestricted",
    };

    private static UnicodeData LoadData()
    {
        var assembly = typeof(IdnHomographDetector).Assembly;
        var confusables = ParseConfusables(Open(assembly, "confusables-17.0.0.txt"));
        var scripts = ParseScripts(Open(assembly, "Scripts-17.0.0.txt"));
        return new(confusables, scripts);
    }

    private static Stream Open(Assembly assembly, string suffix)
    {
        var name = assembly.GetManifestResourceNames().Single(n => n.EndsWith(suffix, StringComparison.Ordinal));
        return assembly.GetManifestResourceStream(name) ?? throw new InvalidOperationException($"Missing embedded resource {suffix}.");
    }

    internal static IReadOnlyDictionary<int, string> ParseConfusables(Stream stream)
    {
        var result = new Dictionary<int, string>();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            var data = line.Split('#', 2)[0].Trim();
            if (data.Length == 0) continue;
            var columns = data.Split(';', StringSplitOptions.TrimEntries);
            if (columns.Length < 2 || !int.TryParse(columns[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var source)) continue;
            var target = string.Concat(columns[1].Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(static token => Rune.TryCreate(int.Parse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture), out var rune)
                    ? rune.ToString() : string.Empty));
            if (target.Length != 0) result[source] = target;
        }
        return result;
    }

    private static IReadOnlyList<ScriptRange> ParseScripts(Stream stream)
    {
        var result = new List<ScriptRange>();
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            var data = line.Split('#', 2)[0].Trim();
            if (data.Length == 0) continue;
            var columns = data.Split(';', StringSplitOptions.TrimEntries);
            if (columns.Length < 2) continue;
            var bounds = columns[0].Split("..", StringSplitOptions.TrimEntries);
            if (!int.TryParse(bounds[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var first)) continue;
            var last = bounds.Length == 1 ? first : int.Parse(bounds[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            result.Add(new(first, last, columns[1]));
        }
        return result.OrderBy(static range => range.First).ToArray();
    }

    private sealed record DomainFacts(string Ascii, string Unicode, string Skeleton, bool IsIdn,
        IReadOnlyList<string> Scripts, IdnRestrictionLevel RestrictionLevel, bool HasConfusableMapping);
    private sealed record ScriptRange(int First, int Last, string Script);
    private sealed record UnicodeData(IReadOnlyDictionary<int, string> Confusables, IReadOnlyList<ScriptRange> Scripts)
    {
        public string ScriptOf(int codePoint)
        {
            var low = 0;
            var high = Scripts.Count - 1;
            while (low <= high)
            {
                var middle = low + ((high - low) / 2);
                var range = Scripts[middle];
                if (codePoint < range.First) high = middle - 1;
                else if (codePoint > range.Last) low = middle + 1;
                else return range.Script;
            }
            return "Unknown";
        }
    }

    private sealed class MatchKeyComparer : IEqualityComparer<(IdnDomainSource Source, string Domain)>
    {
        public static readonly MatchKeyComparer Instance = new();
        public bool Equals((IdnDomainSource Source, string Domain) x, (IdnDomainSource Source, string Domain) y) =>
            x.Source == y.Source && x.Domain.Equals(y.Domain, StringComparison.Ordinal);
        public int GetHashCode((IdnDomainSource Source, string Domain) obj) => HashCode.Combine(obj.Source, obj.Domain);
    }
}
