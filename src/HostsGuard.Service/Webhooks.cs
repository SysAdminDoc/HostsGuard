using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HostsGuard.Contracts;

namespace HostsGuard.Service;

/// <summary>
/// Outbound event-webhook config (NET-044b), persisted in the ACL-locked service
/// data dir so the shared <c>Secret</c> stays SYSTEM+Admins-only. A subscriber
/// (the loopback-API webhook delivery leg) POSTs each engine event to the
/// configured URLs, signed with an <c>X-HG-Signature</c> HMAC of the body.
/// </summary>
public sealed class WebhookConfig
{
    public List<string> Urls { get; set; } = new();

    public string Secret { get; set; } = string.Empty;

    /// <summary>Deliver only when at least one URL is configured.</summary>
    public bool Enabled => Urls.Count > 0;

    private const string FileName = "webhooks.json";

    public static WebhookConfig Load(string dataDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        var path = Path.Combine(dataDir, FileName);
        try
        {
            if (File.Exists(path))
            {
                return JsonSerializer.Deserialize<WebhookConfig>(File.ReadAllText(path)) ?? new WebhookConfig();
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // Corrupt/unreadable config = no webhooks, rather than a startup fault.
        }

        return new WebhookConfig();
    }

    public void Save(string dataDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        Directory.CreateDirectory(dataDir);
        var tmp = Path.Combine(dataDir, FileName + ".tmp");
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, Path.Combine(dataDir, FileName), overwrite: true);
    }
}

/// <summary>GitHub-style webhook body signature. Pure — trivially testable.</summary>
public static class WebhookSignature
{
    /// <summary><c>sha256=&lt;hex hmac&gt;</c> of <paramref name="body"/> keyed by <paramref name="secret"/>.</summary>
    public static string Compute(string? secret, string body)
    {
        ArgumentNullException.ThrowIfNull(body);
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret ?? string.Empty));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(body));
        return "sha256=" + Convert.ToHexString(hash).ToLowerInvariant();
    }
}

/// <summary>
/// Sends one signed webhook POST and returns the HTTP status (0 for a transport
/// error). Injectable so <see cref="WebhookDeliverer"/> is testable without a
/// socket or wall-clock delays.
/// </summary>
public delegate Task<int> WebhookSender(string url, string body, string signature, CancellationToken ct);

/// <summary>
/// Delivers engine events (the <see cref="ActivityEvent"/> bus stream) to the
/// configured webhook URLs with an <c>X-HG-Signature</c> HMAC and bounded
/// exponential-backoff retries. Logging is leak-safe — only the URL host and
/// attempt/status, never the secret or body.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WebhookDeliverer : IDisposable
{
    private readonly WebhookConfig _config;
    private readonly WebhookSender _sender;
    private readonly Action<string>? _log;
    private readonly int _maxAttempts;
    private readonly TimeSpan _backoffBase;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public WebhookDeliverer(
        WebhookConfig config, WebhookSender sender, Action<string>? log = null,
        int maxAttempts = 3, TimeSpan? backoffBase = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _sender = sender ?? throw new ArgumentNullException(nameof(sender));
        _log = log;
        _maxAttempts = Math.Clamp(maxAttempts, 1, 10);
        _backoffBase = backoffBase ?? TimeSpan.FromSeconds(1);
    }

    /// <summary>Subscribe to the engine-event stream and deliver each event.</summary>
    public void Start(EventBus bus)
    {
        ArgumentNullException.ThrowIfNull(bus);
        _loop = Task.Run(() => LoopAsync(bus, _cts.Token));
    }

    private async Task LoopAsync(EventBus bus, CancellationToken ct)
    {
        using var sub = bus.Subscribe<ActivityEvent>();
        try
        {
            await foreach (var ev in sub.Reader.ReadAllAsync(ct))
            {
                await DeliverAsync(BuildPayload(ev), ct);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
    }

    /// <summary>The JSON body posted for one engine event.</summary>
    public static string BuildPayload(ActivityEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        return new JsonObject
        {
            ["event"] = "activity",
            ["ts"] = ev.Ts?.ToDateTime().ToString("o", System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            ["domain"] = ev.Domain,
            ["action"] = ev.Action,
            ["process"] = ev.Process,
            ["details"] = ev.Details,
            ["reason"] = ev.Reason,
        }.ToJsonString();
    }

    /// <summary>Deliver one payload to every configured URL (independent retries).</summary>
    public async Task DeliverAsync(string payload, CancellationToken ct)
    {
        if (!_config.Enabled)
        {
            return;
        }

        var signature = WebhookSignature.Compute(_config.Secret, payload);
        foreach (var url in _config.Urls)
        {
            await DeliverToAsync(url, payload, signature, ct);
        }
    }

    private async Task DeliverToAsync(string url, string body, string signature, CancellationToken ct)
    {
        var host = SafeHost(url);
        for (var attempt = 1; attempt <= _maxAttempts; attempt++)
        {
            int status;
            try
            {
                status = await _sender(url, body, signature, ct);
            }
            catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or TaskCanceledException or IOException)
            {
                status = 0; // transport error — retryable
            }

            if (status is >= 200 and < 300)
            {
                _log?.Invoke($"webhook {host} delivered ({status})");
                return;
            }

            // Retry transport errors, 429, and 5xx; a 4xx means the endpoint
            // rejected the request — retrying won't help.
            var retryable = status == 0 || status == 429 || status >= 500;
            if (!retryable || attempt == _maxAttempts)
            {
                _log?.Invoke($"webhook {host} failed after {attempt} attempt(s) (last status {status})");
                return;
            }

            try
            {
                await Task.Delay(_backoffBase * Math.Pow(2, attempt - 1), ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>Host only (never the full URL, which may carry a token in the path/query).</summary>
    private static string SafeHost(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var u) ? u.Host : "(invalid url)";

    /// <summary>Production HTTP sender: POST JSON with the signature header.</summary>
    public static WebhookSender HttpSender(System.Net.Http.HttpClient http)
    {
        ArgumentNullException.ThrowIfNull(http);
        return async (url, body, signature, ct) =>
        {
            using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Post, url)
            {
                Content = new System.Net.Http.StringContent(body, Encoding.UTF8, "application/json"),
            };
            request.Headers.TryAddWithoutValidation("X-HG-Signature", signature);
            request.Headers.TryAddWithoutValidation("User-Agent", "HostsGuard-Webhook");
            using var response = await http.SendAsync(request, ct);
            return (int)response.StatusCode;
        };
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }
}
