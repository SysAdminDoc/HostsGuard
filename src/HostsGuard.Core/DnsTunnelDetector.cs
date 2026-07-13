namespace HostsGuard.Core;

public sealed record DnsRecordTypeCount(string RecordType, int Count, double Ratio);

public sealed record DnsTunnelDetection(
    string Version,
    string RootDomain,
    string ProcessName,
    int ProcessId,
    int QueryCount,
    int UniqueQueryCount,
    double UniqueQueryRatio,
    double UniqueQueryRatioThreshold,
    DateTime WindowStartUtc,
    DateTime ObservedAtUtc,
    double WindowSeconds,
    double QueriesPerSecond,
    double QueriesPerSecondThreshold,
    double AverageSubdomainLength,
    int MaximumSubdomainLength,
    int LongSubdomainCount,
    double LongSubdomainRatio,
    int SubdomainLengthThreshold,
    double LongSubdomainRatioThreshold,
    double AverageSubdomainEntropy,
    double MaximumSubdomainEntropy,
    int HighEntropyCount,
    double HighEntropyRatio,
    double SubdomainEntropyThreshold,
    double HighEntropyRatioThreshold,
    IReadOnlyList<DnsRecordTypeCount> RecordTypes,
    int SuspiciousRecordTypeCount,
    double SuspiciousRecordTypeRatio,
    double SuspiciousRecordTypeRatioThreshold,
    int SignalCount,
    int DecisionThreshold,
    IReadOnlyList<string> SampleQueries);

public sealed record DnsTunnelDetectorOptions
{
    public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(1);
    public TimeSpan Cooldown { get; init; } = TimeSpan.FromMinutes(5);
    public int MinimumQueries { get; init; } = 20;
    public int SubdomainLengthThreshold { get; init; } = 20;
    public double LongSubdomainRatioThreshold { get; init; } = 0.75;
    public double SubdomainEntropyThreshold { get; init; } = 3.5;
    public double HighEntropyRatioThreshold { get; init; } = 0.75;
    public double UniqueQueryRatioThreshold { get; init; } = 0.85;
    public double QueriesPerSecondThreshold { get; init; } = 0.5;
    public double SuspiciousRecordTypeRatioThreshold { get; init; } = 0.2;
    public int DecisionThreshold { get; init; } = 4;
    public int MaxAggregates { get; init; } = 2048;
    public int MaxObservationsPerAggregate { get; init; } = 256;
    public int MaxSampleQueries { get; init; } = 8;
}

/// <summary>
/// Bounded, deterministic detector for DNS-query bursts carrying high-entropy
/// payloads in subdomains. State and alert cooldowns are isolated by process and
/// registrable root. The detector only reports evidence; it never blocks traffic.
/// </summary>
public sealed class DnsTunnelDetector
{
    public const string EvidenceVersion = "dns-tunnel-score-v1";

    private static readonly IReadOnlySet<string> SuspiciousRecordTypes =
        new HashSet<string>(StringComparer.Ordinal) { "NULL", "TXT", "10", "16" };

    private readonly DnsTunnelDetectorOptions _options;
    private readonly object _gate = new();
    private readonly Dictionary<AggregateKey, AggregateState> _aggregates = new();
    private int _detectionCount;

    public DnsTunnelDetector(DnsTunnelDetectorOptions? options = null)
    {
        _options = options ?? new DnsTunnelDetectorOptions();
        Validate(_options);
    }

    public int TrackedAggregateCount
    {
        get { lock (_gate) return _aggregates.Count; }
    }

    public int BufferedObservationCount
    {
        get { lock (_gate) return _aggregates.Values.Sum(state => state.Observations.Count); }
    }

    /// <summary>Total detections emitted during this process lifetime; contains no query data.</summary>
    public int DetectionCount
    {
        get { lock (_gate) return _detectionCount; }
    }

    public DnsTunnelDetection? Observe(
        string? queryName,
        string? processName,
        int processId,
        string? recordType,
        DateTime timestampUtc)
    {
        var query = Domains.ToAscii(queryName);
        if (!Domains.LooksLikeDomain(query))
        {
            return null;
        }

        var root = Domains.GetRoot(query);
        var payload = ExtractPayload(query, root);
        var normalizedProcess = (processName ?? string.Empty).Trim();
        var key = new AggregateKey(root, normalizedProcess.ToLowerInvariant(), Math.Max(0, processId));
        var observedAt = timestampUtc.Kind == DateTimeKind.Utc
            ? timestampUtc
            : timestampUtc.ToUniversalTime();
        var observation = new Observation(
            observedAt,
            query,
            PayloadLength(payload),
            ShannonEntropy(payload),
            NormalizeRecordType(recordType));

        lock (_gate)
        {
            PruneAggregates(observedAt);
            if (!_aggregates.TryGetValue(key, out var state))
            {
                EvictOldestAggregateIfFull();
                state = new AggregateState(normalizedProcess);
                _aggregates.Add(key, state);
            }

            // An event older than the active window cannot affect the aggregate.
            // Ignoring it also prevents delayed ETW delivery from rewinding state.
            var effectiveNow = state.LastSeenUtc > observedAt ? state.LastSeenUtc : observedAt;
            if (observedAt < effectiveNow - _options.Window)
            {
                return null;
            }

            state.LastSeenUtc = effectiveNow;
            state.Observations.Add(observation);
            state.Observations.RemoveAll(item => item.TimestampUtc < effectiveNow - _options.Window);
            while (state.Observations.Count > _options.MaxObservationsPerAggregate)
            {
                var oldestIndex = state.Observations.FindIndex(item =>
                    item.TimestampUtc == state.Observations.Min(entry => entry.TimestampUtc));
                state.Observations.RemoveAt(oldestIndex);
            }

            var evidence = BuildEvidence(key, state, effectiveNow);
            if (evidence.QueryCount < _options.MinimumQueries ||
                evidence.SignalCount < _options.DecisionThreshold ||
                (state.LastAlertUtc is { } last && effectiveNow - last < _options.Cooldown))
            {
                return null;
            }

            state.LastAlertUtc = effectiveNow;
            _detectionCount++;
            return evidence;
        }
    }

    private DnsTunnelDetection BuildEvidence(AggregateKey key, AggregateState state, DateTime observedAt)
    {
        var observations = state.Observations;
        var count = observations.Count;
        var windowStart = observations.Min(item => item.TimestampUtc);
        var windowSeconds = Math.Max(0, (observedAt - windowStart).TotalSeconds);
        var uniqueCount = observations.Select(item => item.Query).Distinct(StringComparer.Ordinal).Count();
        var longCount = observations.Count(item => item.PayloadLength >= _options.SubdomainLengthThreshold);
        var entropyCount = observations.Count(item => item.PayloadEntropy >= _options.SubdomainEntropyThreshold);
        var suspiciousCount = observations.Count(item => SuspiciousRecordTypes.Contains(item.RecordType));
        var uniqueRatio = Ratio(uniqueCount, count);
        var longRatio = Ratio(longCount, count);
        var entropyRatio = Ratio(entropyCount, count);
        var suspiciousRatio = Ratio(suspiciousCount, count);
        var rate = count / Math.Max(1, windowSeconds);
        var recordTypes = observations
            .GroupBy(item => item.RecordType, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal)
            .Select(group => new DnsRecordTypeCount(group.Key, group.Count(), Ratio(group.Count(), count)))
            .ToArray();
        var signalCount =
            (longRatio >= _options.LongSubdomainRatioThreshold ? 1 : 0) +
            (entropyRatio >= _options.HighEntropyRatioThreshold ? 1 : 0) +
            (uniqueRatio >= _options.UniqueQueryRatioThreshold ? 1 : 0) +
            (rate >= _options.QueriesPerSecondThreshold ? 1 : 0) +
            (suspiciousRatio >= _options.SuspiciousRecordTypeRatioThreshold ? 1 : 0);

        return new DnsTunnelDetection(
            EvidenceVersion,
            key.Root,
            state.DisplayProcessName,
            key.ProcessId,
            count,
            uniqueCount,
            uniqueRatio,
            _options.UniqueQueryRatioThreshold,
            windowStart,
            observedAt,
            windowSeconds,
            rate,
            _options.QueriesPerSecondThreshold,
            observations.Average(item => item.PayloadLength),
            observations.Max(item => item.PayloadLength),
            longCount,
            longRatio,
            _options.SubdomainLengthThreshold,
            _options.LongSubdomainRatioThreshold,
            observations.Average(item => item.PayloadEntropy),
            observations.Max(item => item.PayloadEntropy),
            entropyCount,
            entropyRatio,
            _options.SubdomainEntropyThreshold,
            _options.HighEntropyRatioThreshold,
            recordTypes,
            suspiciousCount,
            suspiciousRatio,
            _options.SuspiciousRecordTypeRatioThreshold,
            signalCount,
            _options.DecisionThreshold,
            observations.Select(item => item.Query).Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal).Take(_options.MaxSampleQueries).ToArray());
    }

    private void PruneAggregates(DateTime now)
    {
        var retention = _options.Window + _options.Cooldown;
        foreach (var stale in _aggregates
                     .Where(pair => now - pair.Value.LastSeenUtc > retention)
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            _aggregates.Remove(stale);
        }
    }

    private void EvictOldestAggregateIfFull()
    {
        if (_aggregates.Count < _options.MaxAggregates)
        {
            return;
        }

        var oldest = _aggregates.MinBy(pair => pair.Value.LastSeenUtc).Key;
        _aggregates.Remove(oldest);
    }

    private static string ExtractPayload(string query, string root) =>
        query.Length > root.Length && query.EndsWith('.' + root, StringComparison.Ordinal)
            ? query[..^(root.Length + 1)]
            : string.Empty;

    private static int PayloadLength(string payload) => payload.Count(char.IsAsciiLetterOrDigit);

    private static double ShannonEntropy(string payload)
    {
        var symbols = payload.Where(char.IsAsciiLetterOrDigit).ToArray();
        if (symbols.Length == 0)
        {
            return 0;
        }

        var entropy = 0.0;
        foreach (var count in symbols.GroupBy(symbol => symbol).Select(group => group.Count()))
        {
            var probability = count / (double)symbols.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static string NormalizeRecordType(string? recordType)
    {
        var normalized = (recordType ?? string.Empty).Trim().ToUpperInvariant();
        return normalized.Length == 0 ? "UNKNOWN" : normalized;
    }

    private static double Ratio(int numerator, int denominator) =>
        numerator / (double)Math.Max(1, denominator);

    private static void Validate(DnsTunnelDetectorOptions options)
    {
        if (options.Window <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.Cooldown < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.MinimumQueries < 2) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.SubdomainLengthThreshold < 1) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.QueriesPerSecondThreshold <= 0) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.DecisionThreshold is < 1 or > 5) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.MaxAggregates < 1) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.MaxObservationsPerAggregate < options.MinimumQueries) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.MaxSampleQueries < 1) throw new ArgumentOutOfRangeException(nameof(options));
        foreach (var ratio in new[]
                 {
                     options.LongSubdomainRatioThreshold,
                     options.HighEntropyRatioThreshold,
                     options.UniqueQueryRatioThreshold,
                     options.SuspiciousRecordTypeRatioThreshold,
                 })
        {
            if (double.IsNaN(ratio) || double.IsInfinity(ratio) || ratio < 0 || ratio > 1)
            {
                throw new ArgumentOutOfRangeException(nameof(options));
            }
        }
        if (double.IsNaN(options.SubdomainEntropyThreshold) ||
            double.IsInfinity(options.SubdomainEntropyThreshold) ||
            options.SubdomainEntropyThreshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options));
        }
    }

    private readonly record struct AggregateKey(string Root, string ProcessName, int ProcessId);
    private sealed record Observation(DateTime TimestampUtc, string Query, int PayloadLength, double PayloadEntropy, string RecordType);

    private sealed class AggregateState(string displayProcessName)
    {
        public string DisplayProcessName { get; } = displayProcessName;
        public List<Observation> Observations { get; } = new();
        public DateTime LastSeenUtc { get; set; }
        public DateTime? LastAlertUtc { get; set; }
    }
}
