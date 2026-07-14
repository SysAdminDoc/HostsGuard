using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using FluentAssertions;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>NET-044: the opt-in loopback JSON-RPC/OpenAPI surface (pure router).</summary>
[SupportedOSPlatform("windows")]
public sealed class LoopbackApiTests : IDisposable
{
    private const string Token = "test-token-0123456789abcdef";

    private readonly string _dir;
    private readonly ServiceState _state;
    private readonly HostsEngine _hosts;
    private readonly LoopbackApi _api;

    public LoopbackApiTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_api_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        var hostsPath = Path.Combine(_dir, "hosts");
        File.WriteAllText(hostsPath, "# hosts\n");
        _hosts = new HostsEngine(hostsPath);
        _state = new ServiceState(_hosts, new HostsDatabase(Path.Combine(_dir, "hostsguard.db")), dataDir: _dir);
        _api = new LoopbackApi(_state, Token);
    }

    public void Dispose()
    {
        _api.Dispose();
        _state.Dispose();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
            // best effort
        }
    }

    private static readonly Dictionary<string, string> NoQuery = new();

    private (int Status, JsonObject Body) Call(string method, string path,
        Dictionary<string, string>? query = null, string? token = Token, string? body = null)
    {
        var (status, json) = _api.Handle(method, path, query ?? NoQuery, token, body);
        return (status, (JsonNode.Parse(json) as JsonObject)!);
    }

    [Fact]
    public void Openapi_needs_no_token_and_advertises_the_port()
    {
        var (status, body) = Call("GET", "/openapi.json", token: null);

        status.Should().Be(200);
        body["servers"]![0]!["url"]!.GetValue<string>().Should().Be($"http://127.0.0.1:{LoopbackApi.DefaultPort}");
    }

    [Fact]
    public void Every_data_route_requires_the_token()
    {
        foreach (var path in new[] { "/status", "/stats", "/domains", "/log" })
        {
            Call("GET", path, token: "wrong").Status.Should().Be(401);
            Call("GET", path, token: null).Status.Should().Be(401);
        }
    }

    [Fact]
    public void Repeated_wrong_tokens_are_rate_limited_but_valid_callers_pass()
    {
        // Injected clock so the token-bucket boundary is deterministic (no sleeps).
        var now = new DateTime(2026, 7, 14, 12, 0, 0, DateTimeKind.Utc);
        using var api = new LoopbackApi(_state, Token, clock: () => now);

        // The burst (15) of wrong tokens all report 401 at a fixed instant...
        for (var i = 0; i < 15; i++)
        {
            api.Handle("GET", "/status", NoQuery, "wrong", null).Status.Should().Be(401);
        }

        // ...the next wrong token, still at the same instant, is throttled to 429.
        api.Handle("GET", "/status", NoQuery, "wrong", null).Status.Should().Be(429);

        // A valid caller is never penalized by an attacker's failures.
        api.Handle("GET", "/status", NoQuery, Token, null).Status.Should().Be(200);

        // One second later the bucket refills one unit → one more wrong try is 401.
        now = now.AddSeconds(1);
        api.Handle("GET", "/status", NoQuery, "wrong", null).Status.Should().Be(401);
        api.Handle("GET", "/status", NoQuery, "wrong", null).Status.Should().Be(429);
    }

    [Fact]
    public void Status_and_stats_report_counts()
    {
        _hosts.Block("ads.example.com");
        _state.Db.AddDomain("ads.example.com", "blocked");

        Call("GET", "/status").Body["blocked"]!.GetValue<int>().Should().Be(1);
        Call("GET", "/stats").Body["blocked"]!.GetValue<int>().Should().Be(1);
    }

    [Fact]
    public void Post_domains_blocks_allows_and_unblocks()
    {
        Call("POST", "/domains", body: """{"action":"block","domain":"tracker.example.com"}""").Status.Should().Be(200);
        _hosts.GetBlocked().Should().Contain("tracker.example.com");

        Call("POST", "/domains", body: """{"action":"unblock","domain":"tracker.example.com"}""").Status.Should().Be(200);
        _hosts.GetBlocked().Should().NotContain("tracker.example.com");
    }

    [Fact]
    public void Post_domains_validates_action_and_domain()
    {
        Call("POST", "/domains", body: """{"action":"nuke","domain":"x.com"}""").Status.Should().Be(400);
        Call("POST", "/domains", body: """{"action":"block","domain":"not a domain"}""").Status.Should().Be(400);
        Call("POST", "/domains", body: "not json").Status.Should().Be(400);
    }

    [Fact]
    public void Log_filters_and_validates_limit()
    {
        _state.Db.LogEvent("a.com", "blocked", reason: "manual");
        _state.Db.LogEvent("b.com", "allowed", reason: "manual");

        var filtered = Call("GET", "/log", new Dictionary<string, string> { ["action"] = "blocked" });
        (filtered.Body["entries"] as JsonArray)!.Should().OnlyContain(e => e!["action"]!.GetValue<string>() == "blocked");

        Call("GET", "/log", new Dictionary<string, string> { ["limit"] = "0" }).Status.Should().Be(400);
    }

    [Fact]
    public void Errors_use_the_stable_shape()
    {
        var (status, body) = Call("GET", "/nope");
        status.Should().Be(404);
        body["error_code"]!.GetValue<string>().Should().StartWith("hostsguard.error.v1/");
    }

    [Fact]
    public void Post_is_refused_when_settings_are_locked()
    {
        _state.Lock.Enable("locked1");
        Call("POST", "/domains", body: """{"action":"block","domain":"x.com"}""").Status.Should().Be(423);
    }

    [Fact]
    public async Task Oversized_chunked_body_is_rejected_even_without_a_content_length()
    {
        // NET-176: a chunked POST reports ContentLength64 == -1 and slips the
        // declared-length guard; the bounded read must still reject it as 413.
        var oversized = new string('x', 1_048_576 + 64);
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(oversized));

        var (body, tooLarge) = await LoopbackApi.ReadBoundedBodyAsync(stream, contentLength: -1);

        tooLarge.Should().BeTrue();
        body.Should().BeNull();
    }

    [Fact]
    public async Task Body_within_the_limit_is_read_intact()
    {
        const string payload = """{"action":"block","domain":"x.com"}""";
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(payload));

        var (body, tooLarge) = await LoopbackApi.ReadBoundedBodyAsync(stream, contentLength: -1);

        tooLarge.Should().BeFalse();
        body.Should().Be(payload);
    }
}
