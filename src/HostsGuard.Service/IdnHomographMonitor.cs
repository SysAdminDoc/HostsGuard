using System.Globalization;
using System.Text;
using HostsGuard.Core;
using HostsGuard.Data;

namespace HostsGuard.Service;

/// <summary>Opt-in, alert-only IDN homograph assessment over local DNS observations.</summary>
public sealed class IdnHomographMonitor
{
    public const string EnabledMetaKey = "idn_homograph_enabled";
    private const int CorpusLimit = 1000;
    private static readonly TimeSpan CorpusTtl = TimeSpan.FromSeconds(30);

    private readonly HostsDatabase _db;
    private readonly IdnHomographDetector _detector;
    private readonly HashSet<string> _alerted = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private Corpus? _corpus;
    private DateTime _corpusAtUtc;

    public IdnHomographMonitor(HostsDatabase db, IdnHomographDetector? detector = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _detector = detector ?? new IdnHomographDetector();
    }

    public bool Enabled => string.Equals(_db.GetMeta(EnabledMetaKey), "on", StringComparison.Ordinal);

    public void SetEnabled(bool enabled) => _db.SetMeta(EnabledMetaKey, enabled ? "on" : "off");

    public int CorpusSize
    {
        get
        {
            var corpus = GetCorpus();
            return corpus.Allowlisted.Concat(corpus.Trusted).Concat(corpus.Recent)
                .Distinct(StringComparer.Ordinal).Count();
        }
    }

    public void Observe(string normalizedDomain, string process)
    {
        if (!Enabled || !Domains.LooksLikeDomain(normalizedDomain))
        {
            return;
        }

        var candidate = Domains.GetRoot(Domains.ToAscii(normalizedDomain));
        var corpus = GetCorpus();
        IdnHomographAssessment assessment;
        try
        {
            assessment = _detector.Analyze(candidate, corpus.Allowlisted, corpus.Trusted, corpus.Recent);
        }
        catch (ArgumentException)
        {
            return;
        }

        if (!assessment.IsSuspicious || assessment.Matches.Count == 0)
        {
            return;
        }

        var match = assessment.Matches[0];
        var dedupe = assessment.AsciiDomain + "|" + match.Domain;
        lock (_gate)
        {
            if (!_alerted.Add(dedupe))
            {
                return;
            }
        }

        var scripts = assessment.Scripts.Count == 0 ? "Unknown" : string.Join('+', assessment.Scripts);
        var details = $"decoded={EscapeUnsafe(assessment.UnicodeDomain)}; " +
            $"punycode={assessment.AsciiDomain}; skeleton={EscapeUnsafe(assessment.Skeleton)}; " +
            $"scripts={scripts}; restriction={assessment.RestrictionLevel}; " +
            $"confusable_target={match.Domain} ({match.Source.ToString().ToLowerInvariant()}); " +
            $"evidence={string.Join(',', assessment.Evidence)}. Alert only; no domain was blocked.";
        _db.AddAlert(
            "idn_homograph",
            "warning",
            "Potential IDN homograph",
            assessment.AsciiDomain,
            details,
            action: "idn_homograph",
            process: process);
    }

    private Corpus GetCorpus()
    {
        lock (_gate)
        {
            if (_corpus is not null && DateTime.UtcNow - _corpusAtUtc < CorpusTtl)
            {
                return _corpus;
            }

            _corpus = BuildCorpus();
            _corpusAtUtc = DateTime.UtcNow;
            return _corpus;
        }
    }

    private Corpus BuildCorpus()
    {
        var allowlisted = new HashSet<string>(StringComparer.Ordinal);
        var trusted = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in _db.GetDomains(status: "whitelisted").Take(CorpusLimit))
        {
            var normalized = Root(row.Domain);
            if (normalized.Length == 0) continue;
            if ((row.Source ?? string.Empty).Contains("allowlist", StringComparison.OrdinalIgnoreCase))
            {
                allowlisted.Add(normalized);
            }
            else
            {
                trusted.Add(normalized);
            }
        }

        var recent = _db.GetFeed(CorpusLimit)
            .Select(static row => Root(row.Domain))
            .Where(domain => domain.Length != 0 && !domain.Contains("xn--", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return new Corpus(allowlisted, trusted, recent);
    }

    private static string Root(string domain)
    {
        var ascii = Domains.ToAscii(domain);
        return Domains.LooksLikeDomain(ascii) ? Domains.GetRoot(ascii) : string.Empty;
    }

    internal static string EscapeUnsafe(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
        {
            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control or UnicodeCategory.Format or
                UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator or
                UnicodeCategory.Surrogate or UnicodeCategory.OtherNotAssigned)
            {
                sb.Append(rune.Value <= ushort.MaxValue ? $"\\u{rune.Value:X4}" : $"\\U{rune.Value:X8}");
            }
            else
            {
                sb.Append(rune.ToString());
            }
        }

        return sb.ToString();
    }

    private sealed record Corpus(
        IReadOnlyCollection<string> Allowlisted,
        IReadOnlyCollection<string> Trusted,
        IReadOnlyCollection<string> Recent);
}
