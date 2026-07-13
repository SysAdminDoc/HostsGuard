using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class DnsTunnelDetectorTests
{
    private static readonly DateTime Start = new(2026, 7, 12, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Malicious_a_record_burst_reports_exact_aggregate_evidence()
    {
        var detector = new DnsTunnelDetector(new DnsTunnelDetectorOptions { MinimumQueries = 24 });

        DnsTunnelDetection? detection = null;
        foreach (var item in TunnelFixture("exfil.test", 24))
        {
            var result = detector.Observe(item.Query, "malware.exe", 731, item.RecordType, item.At);
            detection ??= result;
        }

        detection.Should().NotBeNull();
        detection!.Version.Should().Be(DnsTunnelDetector.EvidenceVersion);
        detection.RootDomain.Should().Be("exfil.test");
        detection.ProcessName.Should().Be("malware.exe");
        detection.ProcessId.Should().Be(731);
        detection.QueryCount.Should().Be(24);
        detection.UniqueQueryCount.Should().Be(24);
        detection.UniqueQueryRatio.Should().Be(1);
        detection.UniqueQueryRatioThreshold.Should().Be(0.85);
        detection.WindowStartUtc.Should().Be(Start);
        detection.ObservedAtUtc.Should().Be(Start.AddSeconds(23));
        detection.WindowSeconds.Should().Be(23);
        detection.QueriesPerSecond.Should().BeApproximately(24d / 23, 0.000001);
        detection.LongSubdomainCount.Should().Be(24);
        detection.LongSubdomainRatio.Should().Be(1);
        detection.HighEntropyCount.Should().Be(24);
        detection.HighEntropyRatio.Should().Be(1);
        detection.RecordTypes.Should().ContainSingle()
            .Which.Should().Be(new DnsRecordTypeCount("A", 24, 1));
        detection.SuspiciousRecordTypeCount.Should().Be(0);
        detection.SignalCount.Should().Be(4);
        detection.DecisionThreshold.Should().Be(4);
        detection.SampleQueries.Should().HaveCount(8).And.BeInAscendingOrder(StringComparer.Ordinal);
    }

    [Fact]
    public void Txt_and_null_mix_is_retained_as_an_additional_signal()
    {
        var detector = new DnsTunnelDetector();
        DnsTunnelDetection? detection = null;
        var fixture = TunnelFixture("command.example", 20).ToArray();
        for (var index = 0; index < fixture.Length; index++)
        {
            var type = index % 2 == 0 ? "TXT" : "NULL";
            var result = detector.Observe(fixture[index].Query, "implant.exe", 94, type, fixture[index].At);
            detection ??= result;
        }

        detection.Should().NotBeNull();
        detection!.SuspiciousRecordTypeCount.Should().Be(20);
        detection.SuspiciousRecordTypeRatio.Should().Be(1);
        detection.RecordTypes.Should().Equal(
            new DnsRecordTypeCount("NULL", 10, 0.5),
            new DnsRecordTypeCount("TXT", 10, 0.5));
        detection.SignalCount.Should().Be(5);
    }

    [Fact]
    public void Suspicious_record_type_mix_can_supply_the_fourth_decision_signal()
    {
        var detector = new DnsTunnelDetector();
        DnsTunnelDetection? detection = null;
        var repeated = TunnelFixture("repeat-txt.example", 20).First().Query;
        for (var index = 0; index < 20; index++)
        {
            detection = detector.Observe(repeated, "implant.exe", 95, "TXT", Start.AddSeconds(index));
        }

        detection.Should().NotBeNull();
        detection!.UniqueQueryRatio.Should().Be(0.05);
        detection.SignalCount.Should().Be(4);
        detection.SuspiciousRecordTypeRatio.Should().Be(1);
    }

    [Theory]
    [MemberData(nameof(BenignFixtures))]
    public void Cdn_and_telemetry_bursts_do_not_alert(IReadOnlyList<QueryFixture> fixture)
    {
        var detector = new DnsTunnelDetector();

        fixture.Select(item => detector.Observe(item.Query, item.Process, item.ProcessId, item.RecordType, item.At))
            .Should().OnlyContain(result => result == null);
    }

    [Fact]
    public void Window_expiry_prevents_slow_queries_from_accumulating()
    {
        var detector = new DnsTunnelDetector();
        var fixture = TunnelFixture("slow.example", 40, spacingSeconds: 5).ToArray();

        fixture.Select(item => detector.Observe(item.Query, "slow.exe", 8, item.RecordType, item.At))
            .Should().OnlyContain(result => result == null);
        detector.BufferedObservationCount.Should().BeLessThan(20);
    }

    [Fact]
    public void Active_burst_alerts_once_but_can_alert_after_window_and_cooldown_expire()
    {
        var detector = new DnsTunnelDetector(new DnsTunnelDetectorOptions
        {
            MinimumQueries = 4,
            Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromSeconds(20),
            MaxObservationsPerAggregate = 16,
        });
        var first = TunnelFixture("repeat.example", 6).ToArray();

        detector.Observe(first[0].Query, "agent.exe", 5, "A", first[0].At).Should().BeNull();
        detector.Observe(first[1].Query, "agent.exe", 5, "A", first[1].At).Should().BeNull();
        detector.Observe(first[2].Query, "agent.exe", 5, "A", first[2].At).Should().BeNull();
        detector.Observe(first[3].Query, "agent.exe", 5, "A", first[3].At).Should().NotBeNull();
        detector.Observe(first[4].Query, "agent.exe", 5, "A", first[4].At).Should().BeNull();
        detector.Observe(first[5].Query, "agent.exe", 5, "A", first[5].At).Should().BeNull();

        DnsTunnelDetection? second = null;
        foreach (var item in TunnelFixture("repeat.example", 4, start: Start.AddSeconds(31)))
        {
            var result = detector.Observe(item.Query, "agent.exe", 5, "A", item.At);
            second ??= result;
        }

        second.Should().NotBeNull();
        second!.WindowStartUtc.Should().Be(Start.AddSeconds(31));
    }

    [Fact]
    public void Aggregates_and_alert_dedupe_are_isolated_by_process_and_root()
    {
        var options = new DnsTunnelDetectorOptions
        {
            MinimumQueries = 4,
            MaxObservationsPerAggregate = 16,
        };
        var detector = new DnsTunnelDetector(options);

        ObserveFixture(detector, TunnelFixture("one.example", 4), "same.exe", 100).Should().NotBeNull();
        ObserveFixture(detector, TunnelFixture("two.example", 4), "same.exe", 100).Should().NotBeNull();
        ObserveFixture(detector, TunnelFixture("one.example", 4), "same.exe", 101).Should().NotBeNull();
        detector.TrackedAggregateCount.Should().Be(3);

        // Process-name casing belongs to the same PID/root aggregate and remains cooldown-deduped.
        var extra = TunnelFixture("one.example", 1, start: Start.AddSeconds(10)).Single();
        detector.Observe(extra.Query, "SAME.EXE", 100, extra.RecordType, extra.At).Should().BeNull();
        detector.TrackedAggregateCount.Should().Be(3);
    }

    [Fact]
    public void Aggregate_and_observation_caps_evict_oldest_state()
    {
        var detector = new DnsTunnelDetector(new DnsTunnelDetectorOptions
        {
            MinimumQueries = 2,
            MaxAggregates = 2,
            MaxObservationsPerAggregate = 3,
        });

        foreach (var item in TunnelFixture("old.example", 5))
        {
            detector.Observe(item.Query, "old.exe", 1, "A", item.At);
        }
        detector.BufferedObservationCount.Should().Be(3);

        detector.Observe(TunnelFixture("second.example", 1).Single().Query, "second.exe", 2, "A", Start.AddSeconds(10));
        detector.Observe(TunnelFixture("third.example", 1).Single().Query, "third.exe", 3, "A", Start.AddSeconds(11));

        detector.TrackedAggregateCount.Should().Be(2);
        detector.BufferedObservationCount.Should().Be(2);
        // The evicted oldest key starts from zero instead of inheriting stale observations.
        var oldAgain = TunnelFixture("old.example", 1, start: Start.AddSeconds(12)).Single();
        detector.Observe(oldAgain.Query, "old.exe", 1, "A", oldAgain.At).Should().BeNull();
    }

    [Fact]
    public void Invalid_names_and_events_older_than_the_window_are_ignored()
    {
        var detector = new DnsTunnelDetector(new DnsTunnelDetectorOptions
        {
            MinimumQueries = 2,
            MaxObservationsPerAggregate = 4,
        });

        detector.Observe("not a domain", "x.exe", 1, "A", Start).Should().BeNull();
        detector.TrackedAggregateCount.Should().Be(0);
        var current = TunnelFixture("ordered.example", 1, start: Start.AddMinutes(2)).Single();
        detector.Observe(current.Query, "x.exe", 1, "A", current.At).Should().BeNull();
        var stale = TunnelFixture("ordered.example", 1).Single();
        detector.Observe(stale.Query, "x.exe", 1, "A", stale.At).Should().BeNull();
        detector.BufferedObservationCount.Should().Be(1);
    }

    public static TheoryData<IReadOnlyList<QueryFixture>> BenignFixtures => new()
    {
        CdnFixture(),
        TelemetryFixture(),
    };

    private static IReadOnlyList<QueryFixture> CdnFixture() => Enumerable.Range(0, 30)
        .Select(index => new QueryFixture(
            $"{CdnTokens[index % CdnTokens.Length]}.assets.cdn.example",
            "browser.exe",
            41,
            index % 4 == 0 ? "AAAA" : "A",
            Start.AddMilliseconds(index * 500)))
        .ToArray();

    private static IReadOnlyList<QueryFixture> TelemetryFixture() => Enumerable.Range(0, 30)
        .Select(index => new QueryFixture(
            $"event-{index:D4}.metrics.example",
            "telemetry.exe",
            42,
            "HTTPS",
            Start.AddMilliseconds(index * 500)))
        .ToArray();

    private static IEnumerable<QueryFixture> TunnelFixture(
        string root,
        int count,
        int spacingSeconds = 1,
        DateTime? start = null)
    {
        var at = start ?? Start;
        for (var index = 0; index < count; index++)
        {
            // Deterministic, high-entropy hex payloads model encoded tunnel chunks.
            var alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
            var offset = index % alphabet.Length;
            var payload = alphabet[offset..] + alphabet[..offset];
            yield return new QueryFixture($"{payload}.{root}", "malware.exe", 731, "A", at.AddSeconds(index * spacingSeconds));
        }
    }

    private static DnsTunnelDetection? ObserveFixture(
        DnsTunnelDetector detector,
        IEnumerable<QueryFixture> fixture,
        string process,
        int processId)
    {
        DnsTunnelDetection? detection = null;
        foreach (var item in fixture)
        {
            var result = detector.Observe(item.Query, process, processId, item.RecordType, item.At);
            detection ??= result;
        }

        return detection;
    }

    private static readonly string[] CdnTokens =
    [
        "f38a5d02176ce44a8bc9d174e94a13d2",
        "971ec4b5049f8c5a84fb84e9ef2d4a11",
        "2b37c51db496a90fe12d391f136207c8",
        "74ed17ac94cf8574ad8c126ab56e7b2d",
    ];

    public sealed record QueryFixture(string Query, string Process, int ProcessId, string RecordType, DateTime At);
}
