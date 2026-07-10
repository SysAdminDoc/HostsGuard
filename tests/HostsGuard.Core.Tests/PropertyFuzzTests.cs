using System.Text;
using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>
/// NET-061 property/fuzz coverage: hosts serialization, blocklist parsing, the
/// search DSL, DoH payload parsing, and redaction are hammered with seeded
/// random inputs — deterministic (fixed seeds), no framework dependency. The
/// invariants matter more than the samples: total functions never throw,
/// cleaning is a fixed point, parsers only emit valid domains, and redaction
/// never leaks a planted public IP.
/// </summary>
public sealed class PropertyFuzzTests
{
    private const int Iterations = 300;

    private static string RandomJunk(Random rng, int maxLen = 60)
    {
        const string alphabet = "abcxyz0129.-_:#!*= \t\"'\\/@%()[]{}|;,~?&^$é中";
        var len = rng.Next(0, maxLen);
        var sb = new StringBuilder(len);
        for (var i = 0; i < len; i++)
        {
            sb.Append(alphabet[rng.Next(alphabet.Length)]);
        }

        return sb.ToString();
    }

    private static string RandomDomain(Random rng)
    {
        var labels = rng.Next(2, 5);
        var sb = new StringBuilder();
        for (var i = 0; i < labels; i++)
        {
            if (i != 0)
            {
                sb.Append('.');
            }

            var len = rng.Next(1, 12);
            for (var j = 0; j < len; j++)
            {
                sb.Append((char)('a' + rng.Next(26)));
            }
        }

        return sb.ToString();
    }

    [Fact]
    public void NormLine_is_total_over_garbage()
    {
        var rng = new Random(4001);
        for (var i = 0; i < Iterations; i++)
        {
            var result = HostsFile.NormLine(RandomJunk(rng));
            if (result is not null)
            {
                result.Should().StartWith("0.0.0.0 ");
            }
        }
    }

    [Fact]
    public void Clean_is_a_fixed_point_over_random_line_soups()
    {
        var rng = new Random(4002);
        for (var i = 0; i < 40; i++)
        {
            var lines = new List<string>();
            var planted = new HashSet<string>(StringComparer.Ordinal);
            for (var j = 0; j < rng.Next(5, 60); j++)
            {
                switch (rng.Next(4))
                {
                    case 0:
                        var d = RandomDomain(rng);
                        planted.Add(d);
                        lines.Add(rng.Next(2) == 0 ? $"0.0.0.0 {d}" : $"127.0.0.1  {d}   # inline");
                        break;
                    case 1:
                        lines.Add("# " + RandomJunk(rng));
                        break;
                    case 2:
                        lines.Add(RandomJunk(rng));
                        break;
                    default:
                        lines.Add(string.Empty);
                        break;
                }
            }

            var once = HostsFile.Clean(lines, version: "9.9.9");
            var twice = HostsFile.Clean(once.Lines, version: "9.9.9");

            twice.Lines.Should().Equal(once.Lines, "cleaning already-clean output must be a fixed point");
            twice.Stats.Dupes.Should().Be(0);
            twice.Stats.Invalid.Should().Be(0);

            // Every planted valid domain survives exactly once.
            var entries = once.Lines.Where(l => l.StartsWith("0.0.0.0 ", StringComparison.Ordinal))
                .Select(l => l["0.0.0.0 ".Length..]).ToList();
            entries.Should().OnlyHaveUniqueItems();
            foreach (var domain in planted)
            {
                entries.Should().Contain(domain);
            }
        }
    }

    [Fact]
    public void Blocklist_parser_is_total_and_emits_only_plausible_domains()
    {
        var rng = new Random(4003);
        for (var i = 0; i < 40; i++)
        {
            var planted = new List<string>();
            var sb = new StringBuilder();
            for (var j = 0; j < rng.Next(5, 80); j++)
            {
                if (rng.Next(3) == 0)
                {
                    var d = RandomDomain(rng);
                    planted.Add(d);
                    sb.AppendLine(rng.Next(2) == 0 ? $"0.0.0.0 {d}" : d);
                }
                else
                {
                    sb.AppendLine(RandomJunk(rng));
                }
            }

            var parsed = BlocklistCatalog.ParseDomains(sb.ToString());

            parsed.Should().OnlyContain(d => Domains.LooksLikeDomain(d));
            foreach (var domain in planted)
            {
                parsed.Should().Contain(domain);
            }
        }
    }

    [Fact]
    public void Search_dsl_is_total_and_empty_query_matches_everything()
    {
        var rng = new Random(4004);
        var record = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["domain"] = "ads.example.com",
            ["status"] = "blocked",
            ["tags"] = new[] { "tracker", "ads" },
            ["hits"] = null,
        };

        SearchQuery.Matches(record, null).Should().BeTrue();
        SearchQuery.Matches(record, "   ").Should().BeTrue();

        for (var i = 0; i < Iterations; i++)
        {
            var query = RandomJunk(rng, 40);
            // Total: any junk parses and evaluates without throwing.
            _ = SearchQuery.Parse(query);
            _ = SearchQuery.Matches(record, query);
        }
    }

    [Fact]
    public void Search_negation_inverts_containment_on_plain_terms()
    {
        var rng = new Random(4005);
        for (var i = 0; i < Iterations; i++)
        {
            var domain = RandomDomain(rng);
            var record = new Dictionary<string, object?>(StringComparer.Ordinal) { ["domain"] = domain };
            var needle = rng.Next(2) == 0
                ? domain[rng.Next(domain.Length / 2)..] // guaranteed substring
                : RandomDomain(rng);                    // usually absent

            var positive = SearchQuery.Matches(record, needle);
            var negative = SearchQuery.Matches(record, "!" + needle);

            negative.Should().Be(!positive, $"'!{needle}' must invert '{needle}' on {domain}");
        }
    }

    [Fact]
    public void Doh_payload_parser_is_total_over_garbage()
    {
        var rng = new Random(4006);
        for (var i = 0; i < Iterations; i++)
        {
            var set = DohResolvers.ParsePayload(RandomJunk(rng, 200));
            set.Should().NotBeNull();
        }
    }

    private static byte[] RandomBytes(Random rng, int maxLen = 128)
    {
        var buf = new byte[rng.Next(0, maxLen)];
        rng.NextBytes(buf);
        return buf;
    }

    [Fact]
    public void ToAscii_is_total_and_idempotent_over_garbage()
    {
        // NET-184: the domain normalizer must never throw on human/policy junk and
        // must be a fixed point (re-normalizing its own output changes nothing).
        var rng = new Random(4008);
        for (var i = 0; i < Iterations; i++)
        {
            var junk = RandomJunk(rng, 80);
            var once = Domains.ToAscii(junk);
            Domains.ToAscii(once).Should().Be(once);
            _ = Domains.LooksLikeDomain(junk); // total: never throws
        }
    }

    [Fact]
    public void Svcb_parser_is_total_over_random_bytes()
    {
        // NET-184: DDR SVCB RDATA arrives off the wire; parsing must never throw.
        var rng = new Random(4009);
        for (var i = 0; i < Iterations; i++)
        {
            _ = DesignatedResolver.ParseSvcb(RandomBytes(rng));
        }
    }

    [Fact]
    public void TlsClientHello_parser_is_total_over_random_and_truncated_bytes()
    {
        // NET-184: the raw-socket SNI parser reads attacker-influenced bytes.
        var rng = new Random(4010);
        for (var i = 0; i < Iterations; i++)
        {
            var full = RandomBytes(rng, 300);
            _ = TlsClientHello.TryParse(full);
            // Also hammer every truncation of a plausible handshake prefix.
            var cut = rng.Next(0, full.Length + 1);
            _ = TlsClientHello.TryParse(full.AsSpan(0, cut));
        }
    }

    [Fact]
    public void PortablePolicy_FromJson_only_throws_documented_types_over_garbage()
    {
        // NET-184: policy import is untrusted; malformed input must surface only
        // the documented failure types, never an unhandled crash (NRE, overflow…).
        var rng = new Random(4011);
        var fragments = new[] { "{", "}", "[]", "null", "true", "\"x\"", "{\"version\":", "{\"version\":999999}", "{\"blocked\":[" };
        for (var i = 0; i < Iterations; i++)
        {
            var json = rng.Next(2) == 0 ? RandomJunk(rng, 120) : fragments[rng.Next(fragments.Length)] + RandomJunk(rng, 40);
            try
            {
                _ = PortablePolicy.FromJson(json);
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException
                or InvalidOperationException or ArgumentException or NotSupportedException)
            {
                // Documented, expected failure modes for malformed policy input.
            }
        }
    }

    [Fact]
    public void Redaction_never_leaks_planted_public_ips()
    {
        var rng = new Random(4007);
        for (var i = 0; i < Iterations; i++)
        {
            var ip = $"{rng.Next(11, 223)}.{rng.Next(256)}.{rng.Next(256)}.{rng.Next(1, 255)}";
            if (!Redaction.LooksLikePublicIp(ip))
            {
                continue; // skipped: generated a private/reserved range
            }

            var text = $"{RandomJunk(rng, 30)} contacted {ip} {RandomJunk(rng, 30)}";

            Redaction.RedactText(text).Should().NotContain(ip);
        }
    }
}
