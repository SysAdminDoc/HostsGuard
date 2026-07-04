using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using FluentAssertions;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;
using Microsoft.Data.Sqlite;
using Xunit;

namespace HostsGuard.Service.Tests;

/// <summary>
/// NET-044b: outbound event webhooks — HMAC signature, config persistence,
/// bounded-retry delivery, and the loopback-API config surface (secret redacted).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WebhooksTests : IDisposable
{
    private readonly string _dir;

    public WebhooksTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "hg_wh_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    [Fact]
    public void Signature_is_a_stable_hmac_sha256()
    {
        var sig = WebhookSignature.Compute("s3cret", "{\"a\":1}");
        sig.Should().StartWith("sha256=").And.HaveLength("sha256=".Length + 64);
        WebhookSignature.Compute("s3cret", "{\"a\":1}").Should().Be(sig);      // deterministic
        WebhookSignature.Compute("other", "{\"a\":1}").Should().NotBe(sig);    // keyed by secret
    }

    [Fact]
    public void Config_round_trips_through_the_data_dir()
    {
        new WebhookConfig { Urls = { "https://example.com/hook" }, Secret = "k" }.Save(_dir);
        var loaded = WebhookConfig.Load(_dir);
        loaded.Urls.Should().ContainSingle().Which.Should().Be("https://example.com/hook");
        loaded.Secret.Should().Be("k");
        loaded.Enabled.Should().BeTrue();
    }

    private sealed class FakeSender
    {
        private readonly Queue<int> _statuses;
        public List<(string Url, string Body, string Sig)> Calls { get; } = new();

        public FakeSender(params int[] statuses) => _statuses = new Queue<int>(statuses);

        public WebhookSender Delegate => (url, body, sig, ct) =>
        {
            Calls.Add((url, body, sig));
            return Task.FromResult(_statuses.Count > 0 ? _statuses.Dequeue() : 200);
        };
    }

    private static WebhookDeliverer Deliverer(WebhookConfig cfg, WebhookSender sender)
        => new(cfg, sender, log: null, maxAttempts: 3, backoffBase: TimeSpan.Zero);

    [Fact]
    public async Task Delivers_with_signature_header_to_each_url()
    {
        var cfg = new WebhookConfig { Urls = { "https://a.example/hook", "https://b.example/hook" }, Secret = "k" };
        var sender = new FakeSender(200, 200);
        using var d = Deliverer(cfg, sender.Delegate);

        await d.DeliverAsync("{\"event\":\"activity\"}", CancellationToken.None);

        sender.Calls.Should().HaveCount(2);
        sender.Calls[0].Sig.Should().Be(WebhookSignature.Compute("k", "{\"event\":\"activity\"}"));
        sender.Calls.Select(c => c.Url).Should().BeEquivalentTo("https://a.example/hook", "https://b.example/hook");
    }

    [Fact]
    public async Task Retries_a_5xx_then_succeeds()
    {
        var cfg = new WebhookConfig { Urls = { "https://a.example/hook" } };
        var sender = new FakeSender(503, 200);
        using var d = Deliverer(cfg, sender.Delegate);

        await d.DeliverAsync("{}", CancellationToken.None);

        sender.Calls.Should().HaveCount(2); // retried once, then 200
    }

    [Fact]
    public async Task Gives_up_after_max_attempts_on_persistent_failure()
    {
        var cfg = new WebhookConfig { Urls = { "https://a.example/hook" } };
        var sender = new FakeSender(500, 500, 500, 500);
        using var d = Deliverer(cfg, sender.Delegate);

        await d.DeliverAsync("{}", CancellationToken.None);

        sender.Calls.Should().HaveCount(3); // maxAttempts, no 4th
    }

    [Fact]
    public async Task Does_not_retry_a_4xx()
    {
        var cfg = new WebhookConfig { Urls = { "https://a.example/hook" } };
        var sender = new FakeSender(404, 200);
        using var d = Deliverer(cfg, sender.Delegate);

        await d.DeliverAsync("{}", CancellationToken.None);

        sender.Calls.Should().HaveCount(1); // 404 is terminal
    }

    [Fact]
    public async Task Disabled_config_delivers_nothing()
    {
        var sender = new FakeSender();
        using var d = Deliverer(new WebhookConfig(), sender.Delegate);
        await d.DeliverAsync("{}", CancellationToken.None);
        sender.Calls.Should().BeEmpty();
    }

    [Fact]
    public void BuildPayload_includes_the_event_fields()
    {
        var payload = WebhookDeliverer.BuildPayload(new ActivityEvent
        {
            Domain = "ads.example.com", Action = "blocked", Process = "chrome", Details = "hosts", Reason = "manual",
        });
        var obj = JsonNode.Parse(payload)!.AsObject();
        obj["event"]!.GetValue<string>().Should().Be("activity");
        obj["domain"]!.GetValue<string>().Should().Be("ads.example.com");
        obj["action"]!.GetValue<string>().Should().Be("blocked");
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void Loopback_configures_webhooks_and_redacts_the_secret()
    {
        File.WriteAllText(Path.Combine(_dir, "hosts"), "# hosts\n");
        using var state = new ServiceState(
            new HostsEngine(Path.Combine(_dir, "hosts")),
            new HostsDatabase(Path.Combine(_dir, "hostsguard.db")), dataDir: _dir);
        const string token = "test-token-0123456789abcdef";
        using var api = new LoopbackApi(state, token);

        var (setStatus, setJson) = api.Handle("POST", "/webhooks", new Dictionary<string, string>(), token,
            "{\"urls\":[\"https://sink.example/hook\"],\"secret\":\"topsecret\"}");
        setStatus.Should().Be(200);
        JsonNode.Parse(setJson)!["ok"]!.GetValue<bool>().Should().BeTrue();
        state.Webhooks.Urls.Should().ContainSingle().Which.Should().Be("https://sink.example/hook");

        var (getStatus, getJson) = api.Handle("GET", "/webhooks", new Dictionary<string, string>(), token, null);
        getStatus.Should().Be(200);
        var body = JsonNode.Parse(getJson)!.AsObject();
        body["secret_set"]!.GetValue<bool>().Should().BeTrue();
        getJson.Should().NotContain("topsecret"); // never leaked

        var (badStatus, _) = api.Handle("POST", "/webhooks", new Dictionary<string, string>(), token,
            "{\"urls\":[\"ftp://nope\"]}");
        badStatus.Should().Be(400);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { /* best effort */ }
    }
}
