using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace HostsGuard.Service;

/// <summary>
/// Optional headless JSON-RPC/OpenAPI loopback (NET-044). OFF by default; the
/// host starts it only when <c>HG_LOOPBACK_API</c> is truthy. Binds
/// <c>127.0.0.1:HG_PORT</c> (default 7847), token-authed via <c>X-HG-Token</c>
/// (minted to an ACL-locked file), 1 MB body cap, stable
/// <c>hostsguard.error.v1</c> error shape. Read endpoints:
/// <c>GET /status /domains /stats /log /openapi.json</c>; one mutation:
/// <c>POST /domains {action, domain}</c>. Request routing is a pure method so
/// the surface is fully testable without a socket.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LoopbackApi : IDisposable
{
    public const int DefaultPort = 7847;
    private const int MaxBodyBytes = 1_048_576;

    private readonly ServiceState _state;
    private readonly string _token;
    private readonly int _port;
    private HttpListener? _listener;
    private Task? _loop;
    private readonly CancellationTokenSource _cts = new();

    public LoopbackApi(ServiceState state, string token, int port = DefaultPort)
    {
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _token = token ?? throw new ArgumentNullException(nameof(token));
        _port = port is > 0 and < 65536 ? port : DefaultPort;
    }

    /// <summary>Resolve enablement + port from the environment (opt-in).</summary>
    public static bool IsEnabled() =>
        (Environment.GetEnvironmentVariable("HG_LOOPBACK_API") ?? string.Empty).Trim() is "1" or "true" or "yes";

    public static int PortFromEnv() =>
        int.TryParse(Environment.GetEnvironmentVariable("HG_PORT"), out var p) && p is > 0 and < 65536 ? p : DefaultPort;

    /// <summary>Mint (or reuse) the loopback token in the ACL-locked data dir.</summary>
    public static string EnsureToken(string dataDir)
    {
        var path = Path.Combine(dataDir, "loopback_token");
        if (File.Exists(path))
        {
            var existing = File.ReadAllText(path).Trim();
            if (existing.Length >= 32)
            {
                return existing;
            }
        }

        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        File.WriteAllText(path, token);
        return token;
    }

    public void Start()
    {
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
        _listener.Start();
        _loop = Task.Run(() => LoopAsync(_cts.Token));
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is { IsListening: true })
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync();
            }
            catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }

            try
            {
                await ServeAsync(ctx);
            }
            catch (Exception ex) when (ex is HttpListenerException or IOException or ObjectDisposedException)
            {
                // Client vanished mid-response — nothing to do.
            }
        }
    }

    private async Task ServeAsync(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        string? body = null;
        if (req.HttpMethod == "POST")
        {
            if (req.ContentLength64 > MaxBodyBytes)
            {
                await WriteAsync(ctx, 413, Error("body_too_large", "request body exceeds 1 MB"));
                return;
            }

            using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
            var buffer = new char[MaxBodyBytes];
            var read = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
            body = new string(buffer, 0, read);
        }

        var (status, json) = await HandleAsync(
            req.HttpMethod,
            req.Url?.AbsolutePath ?? "/",
            req.QueryString.AllKeys.Where(k => k is not null)
                .ToDictionary(k => k!, k => req.QueryString[k] ?? string.Empty, StringComparer.OrdinalIgnoreCase),
            req.Headers["X-HG-Token"],
            body,
            _cts.Token);

        await WriteAsync(ctx, status, json);
    }

    private static async Task WriteAsync(HttpListenerContext ctx, int status, string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = bytes.Length;
        await ctx.Response.OutputStream.WriteAsync(bytes);
        ctx.Response.Close();
    }

    /// <summary>Pure request router — (status, json). Fully testable without a socket.</summary>
    public (int Status, string Json) Handle(
        string method, string path, IReadOnlyDictionary<string, string> query, string? token, string? body)
        => HandleAsync(method, path, query, token, body, CancellationToken.None).GetAwaiter().GetResult();

    /// <summary>Async request router for routes that validate service-owned egress.</summary>
    public async Task<(int Status, string Json)> HandleAsync(
        string method, string path, IReadOnlyDictionary<string, string> query, string? token, string? body,
        CancellationToken ct)
    {
        if (path == "/openapi.json" && method == "GET")
        {
            return (200, OpenApi(_port));
        }

        // Every other route is token-authed (constant-time compare).
        var provided = token ?? string.Empty;
        if (provided.Length != _token.Length ||
            !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(provided), Encoding.UTF8.GetBytes(_token)))
        {
            return (401, Error("unauthorized", "missing or invalid X-HG-Token"));
        }

        return (method, path) switch
        {
            ("GET", "/status") => (200, Status()),
            ("GET", "/stats") => (200, Stats()),
            ("GET", "/domains") => (200, Domains(query)),
            ("GET", "/log") => Log(query),
            ("GET", "/webhooks") => (200, GetWebhooks()),
            ("POST", "/domains") => PostDomain(body),
            ("POST", "/webhooks") => await PostWebhooksAsync(body, ct),
            _ => (404, Error("not_found", $"no route for {method} {path}")),
        };
    }

    private string Status()
    {
        var stats = _state.Db.GetStats();
        var obj = new JsonObject
        {
            ["version"] = typeof(LoopbackApi).Assembly.GetName().Version?.ToString() ?? "0.0.0",
            ["uptime_seconds"] = (long)(DateTime.UtcNow - _state.StartedAtUtc).TotalSeconds,
            ["blocked"] = stats.Blocked,
            ["whitelisted"] = stats.Whitelisted,
            ["feed_total"] = stats.FeedTotal,
            ["today_hits"] = stats.TodayHits,
            ["port"] = _port,
        };
        return obj.ToJsonString();
    }

    private string Stats()
    {
        var s = _state.Db.GetStats();
        return new JsonObject
        {
            ["blocked"] = s.Blocked,
            ["whitelisted"] = s.Whitelisted,
            ["feed_total"] = s.FeedTotal,
            ["today_hits"] = s.TodayHits,
        }.ToJsonString();
    }

    private string Domains(IReadOnlyDictionary<string, string> query)
    {
        var status = query.GetValueOrDefault("status");
        var search = query.GetValueOrDefault("search");
        var rows = _state.Db.GetDomains(string.IsNullOrWhiteSpace(status) ? null : status,
            string.IsNullOrWhiteSpace(search) ? null : search);
        var arr = new JsonArray();
        foreach (var r in rows)
        {
            arr.Add(new JsonObject
            {
                ["domain"] = r.Domain,
                ["status"] = r.Status,
                ["source"] = r.Source,
                ["reason"] = r.Reason,
                ["hits"] = r.Hits,
            });
        }

        return new JsonObject { ["domains"] = arr }.ToJsonString();
    }

    private (int, string) Log(IReadOnlyDictionary<string, string> query)
    {
        var limit = 200;
        if (query.TryGetValue("limit", out var l))
        {
            if (!int.TryParse(l, out limit) || limit is < 1 or > 2000)
            {
                return (400, Error("invalid_argument", "limit must be 1..2000"));
            }
        }

        var action = query.GetValueOrDefault("action");
        var reason = query.GetValueOrDefault("reason");
        var arr = new JsonArray();
        foreach (var (ts, domain, act, process, details, rsn) in _state.Db.GetLog(limit))
        {
            if (!string.IsNullOrWhiteSpace(action) && !string.Equals(act, action, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(reason) && !string.Equals(rsn, reason, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            arr.Add(new JsonObject
            {
                ["ts"] = ts,
                ["domain"] = domain,
                ["action"] = act,
                ["process"] = process,
                ["details"] = details,
                ["reason"] = rsn,
            });
        }

        return (200, new JsonObject { ["entries"] = arr }.ToJsonString());
    }

    private (int, string) PostDomain(string? body)
    {
        if (_state.GateWhenLocked() is not null)
        {
            return (423, Error("locked", "settings are locked"));
        }

        JsonObject? obj;
        try
        {
            obj = JsonNode.Parse(body ?? string.Empty) as JsonObject;
        }
        catch (JsonException)
        {
            return (400, Error("invalid_json", "request body is not valid JSON"));
        }

        var action = (obj?["action"]?.GetValue<string>() ?? string.Empty).Trim().ToLowerInvariant();
        var domain = (obj?["domain"]?.GetValue<string>() ?? string.Empty).Trim().ToLowerInvariant();
        if (domain.Length == 0 || !Core.Domains.LooksLikeDomain(domain))
        {
            return (400, Error("invalid_domain", "a valid 'domain' is required"));
        }

        try
        {
            switch (action)
            {
                case "block":
                    _state.Hosts.Block(domain);
                    _state.Db.AddDomain(domain, "blocked", "loopback");
                    break;
                case "allow":
                    _state.Db.AddDomain(domain, "whitelisted", "loopback");
                    _state.Hosts.Unblock(domain);
                    break;
                case "unblock":
                    _state.Hosts.Unblock(domain);
                    _state.Db.RemoveDomain(domain);
                    break;
                default:
                    return (400, Error("invalid_action", "action must be block|allow|unblock"));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A persistent hosts-file hold (usually AV scanning) must return a
            // clean error, not escape and stop the listener loop.
            return (503, Error("hosts_locked",
                "the hosts file is locked by another program (usually antivirus) — retry shortly"));
        }

        _state.Db.LogEvent(domain, action, details: "loopback api", reason: "loopback");
        return (200, new JsonObject { ["ok"] = true, ["action"] = action, ["domain"] = domain }.ToJsonString());
    }

    // ─── Webhooks (NET-044b): configure the outbound event delivery ──────────

    private string GetWebhooks()
    {
        var urls = new JsonArray();
        foreach (var u in _state.Webhooks.Urls)
        {
            urls.Add(u);
        }

        // The secret is never returned — only whether one is set.
        return new JsonObject
        {
            ["urls"] = urls,
            ["secret_set"] = _state.Webhooks.Secret.Length != 0,
        }.ToJsonString();
    }

    private async Task<(int, string)> PostWebhooksAsync(string? body, CancellationToken ct)
    {
        if (_state.GateWhenLocked() is not null)
        {
            return (423, Error("locked", "settings are locked"));
        }

        JsonObject? obj;
        try
        {
            obj = JsonNode.Parse(body ?? string.Empty) as JsonObject;
        }
        catch (JsonException)
        {
            return (400, Error("invalid_json", "request body is not valid JSON"));
        }

        var urls = new List<string>();
        if (obj?["urls"] is JsonArray arr)
        {
            foreach (var node in arr)
            {
                var u = node?.GetValue<string>()?.Trim() ?? string.Empty;
                if (u.Length == 0)
                {
                    continue;
                }

                try
                {
                    await SsrfGuard.EnsurePublicHttpsAsync(u, ct);
                }
                catch (SsrfBlockedException ex)
                {
                    return (400, Error("invalid_url", ex.Message));
                }

                urls.Add(u);
            }
        }

        _state.Webhooks.Urls = urls;
        // "secret" is write-only: absent keeps the stored secret; "" clears it.
        if (obj?["secret"] is JsonNode s)
        {
            _state.Webhooks.Secret = s.GetValue<string>() ?? string.Empty;
        }

        try
        {
            _state.Webhooks.Save(_state.DataDir);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (503, Error("write_failed", $"could not persist webhook config: {ex.Message}"));
        }

        _state.Db.LogEvent("webhook", "config", details: $"{urls.Count} endpoint(s)", reason: "loopback");
        return (200, new JsonObject { ["ok"] = true, ["urls"] = urls.Count, ["secret_set"] = _state.Webhooks.Secret.Length != 0 }.ToJsonString());
    }

    private static string Error(string code, string message) =>
        new JsonObject { ["error_code"] = $"hostsguard.error.v1/{code}", ["message"] = message }.ToJsonString();

    /// <summary>Minimal OpenAPI 3 doc; the active port is advertised in <c>servers</c>.</summary>
    public static string OpenApi(int port)
    {
        var doc = new JsonObject
        {
            ["openapi"] = "3.0.3",
            ["info"] = new JsonObject { ["title"] = "HostsGuard Loopback API", ["version"] = "1.0" },
            ["servers"] = new JsonArray { new JsonObject { ["url"] = $"http://127.0.0.1:{port}" } },
            ["paths"] = new JsonObject
            {
                ["/status"] = PathGet("Service status + counts"),
                ["/stats"] = PathGet("Domain statistics"),
                ["/domains"] = PathGet("Managed domains"),
                ["/log"] = PathGet("Event log (limit/action/reason filters)"),
                ["/webhooks"] = PathGet("Outbound event-webhook config (secret redacted)"),
                ["/openapi.json"] = PathGet("This document"),
            },
        };
        return doc.ToJsonString();
    }

    private static JsonObject PathGet(string summary) =>
        new() { ["get"] = new JsonObject { ["summary"] = summary, ["responses"] = new JsonObject { ["200"] = new JsonObject { ["description"] = "OK" } } } };

    public void Dispose()
    {
        _cts.Cancel();
        try
        {
            _listener?.Stop();
            _listener?.Close();
        }
        catch (ObjectDisposedException)
        {
            // already closed
        }

        if (_loop is { } loop)
        {
            try
            {
                loop.Wait(TimeSpan.FromSeconds(5));
            }
            catch (AggregateException ex) when (ex.InnerExceptions.All(e => e is OperationCanceledException or ObjectDisposedException))
            {
            }
            catch (AggregateException)
            {
            }
        }

        _cts.Dispose();
    }
}
