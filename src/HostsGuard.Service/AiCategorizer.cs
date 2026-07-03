using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>Persisted AI-categorization settings (ai_config.json, ACL-locked dir).</summary>
public sealed record AiSettings(string ApiKey, string Model, string Endpoint, bool Enabled)
{
    public const string DefaultModel = "deepseek-chat";
    public const string DefaultEndpoint = "https://api.deepseek.com";

    public static AiSettings Empty { get; } = new(string.Empty, DefaultModel, DefaultEndpoint, false);
}

/// <summary>Chat-completion transport, injectable for tests.</summary>
public interface IAiCompleter
{
    /// <summary>Returns the assistant's message content for a one-shot prompt.</summary>
    Task<string> CompleteAsync(AiSettings settings, string systemPrompt, string userPrompt, CancellationToken ct);
}

/// <summary>OpenAI-compatible chat client (DeepSeek's native protocol).</summary>
[SupportedOSPlatform("windows")]
public sealed class DeepSeekCompleter : IAiCompleter, IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(90) };

    public async Task<string> CompleteAsync(AiSettings settings, string systemPrompt, string userPrompt, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var endpoint = settings.Endpoint.TrimEnd('/');
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{endpoint}/chat/completions");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.ApiKey);
        request.Content = new StringContent(JsonSerializer.Serialize(new
        {
            model = settings.Model,
            messages = new object[]
            {
                new { role = "system", content = systemPrompt },
                new { role = "user", content = userPrompt },
            },
            temperature = 0,
            response_format = new { type = "json_object" },
        }), Encoding.UTF8, "application/json");

        using var response = await _http.SendAsync(request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"AI endpoint returned {(int)response.StatusCode}: {Truncate(body)}");
        }

        return JsonNode.Parse(body)?["choices"]?[0]?["message"]?["content"]?.GetValue<string>()
            ?? throw new InvalidOperationException("AI response had no message content");
    }

    private static string Truncate(string s) => s.Length <= 300 ? s : s[..300];

    public void Dispose() => _http.Dispose();
}

/// <summary>
/// AI domain categorization (DeepSeek): stores settings in the ACL-locked data
/// dir, asks the model to bucket domains into hosts-file categories in the
/// user's "# Vendor Type" style, persists categories to the DB, and re-homes
/// the managed hosts entries under their category section headers.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AiCategorizer
{
    private const int BatchSize = 60;
    private const int MaxDomainsPerRun = 600;

    private const string SystemPrompt =
        "You categorize DNS domain names for a hosts-file based content blocker. " +
        "Reply ONLY with a JSON object mapping each input domain to one short category string. " +
        "Prefer vendor-qualified categories in the style \"Google Ads\", \"Google Tracking\", " +
        "\"Facebook/Meta Tracking\", \"Microsoft Telemetry\" when the vendor is clear; otherwise use one of: " +
        "\"Major Ad Networks\", \"Major Trackers\", \"Analytics\", \"Telemetry\", \"Malware\", \"Phishing\", " +
        "\"Cryptomining\", \"Adult\", \"Gambling\", \"Social Media\", \"Gaming\", \"Streaming\", \"CDN\", \"Other\". " +
        "Never invent new formats, never add commentary.";

    private const string PurposePrompt =
        "You explain what DNS domains are for, for users of a network-privacy tool deciding whether to block them. " +
        "Reply ONLY with a JSON object mapping each input domain to one concise purpose description of at most " +
        "8 words, e.g. \"Google display ads serving\", \"Steam game content delivery\", \"Windows telemetry collection\", " +
        "\"Discord voice chat infrastructure\". Say \"Unknown\" only when the domain is truly unidentifiable. " +
        "No commentary, no extra keys.";

    private const string IdentifyPrompt =
        "You explain live outbound network connections for users of a network-privacy tool. Each input line has " +
        "process, resolved host (may be blank), remote IP, and port. Reply ONLY with a JSON object mapping each " +
        "line's KEY (given first on the line) to one concise explanation of at most 10 words describing what the " +
        "connection is likely for, e.g. \"Chrome syncing browsing data to Google\", \"Steam downloading game content\". " +
        "Say \"Unknown\" when unsure. No commentary.";

    private readonly HostsDatabase _db;
    private readonly HostsEngine _hosts;
    private readonly IAiCompleter _completer;
    private readonly string _configPath;
    private readonly object _configGate = new();

    public AiCategorizer(HostsDatabase db, HostsEngine hosts, IAiCompleter completer, string dataDir)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _completer = completer ?? throw new ArgumentNullException(nameof(completer));
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        _configPath = Path.Combine(dataDir, "ai_config.json");
    }

    public AiSettings Settings
    {
        get
        {
            lock (_configGate)
            {
                try
                {
                    if (File.Exists(_configPath))
                    {
                        var node = JsonNode.Parse(File.ReadAllText(_configPath));
                        return new AiSettings(
                            node?["api_key"]?.GetValue<string>() ?? string.Empty,
                            NonEmpty(node?["model"]?.GetValue<string>(), AiSettings.DefaultModel),
                            NonEmpty(node?["endpoint"]?.GetValue<string>(), AiSettings.DefaultEndpoint),
                            node?["enabled"]?.GetValue<bool>() ?? false);
                    }
                }
                catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
                {
                    // Unreadable config = unconfigured.
                }

                return AiSettings.Empty;
            }
        }
    }

    /// <summary>Persist settings; an empty api_key keeps the stored one.</summary>
    public void SaveSettings(string apiKey, string model, string endpoint, bool enabled)
    {
        lock (_configGate)
        {
            var current = Settings;
            var next = new AiSettings(
                string.IsNullOrWhiteSpace(apiKey) ? current.ApiKey : apiKey.Trim(),
                NonEmpty(model, AiSettings.DefaultModel),
                NonEmpty(endpoint, AiSettings.DefaultEndpoint),
                enabled);
            var json = new JsonObject
            {
                ["api_key"] = next.ApiKey,
                ["model"] = next.Model,
                ["endpoint"] = next.Endpoint,
                ["enabled"] = next.Enabled,
            };
            File.WriteAllText(_configPath, json.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    /// <summary>
    /// Categorize <paramref name="domains"/> (batched), persist DB categories,
    /// and re-home the blocked hosts entries under their category sections.
    /// Returns the resolved (domain, category) pairs.
    /// </summary>
    public async Task<IReadOnlyList<(string Domain, string Category)>> CategorizeAsync(
        IReadOnlyList<string> domains, CancellationToken ct, IReadOnlyList<string>? preferredCategories = null)
    {
        ArgumentNullException.ThrowIfNull(domains);
        var cleaned = domains
            .Select(d => d.ToLowerInvariant().Trim())
            .Where(Core.Domains.LooksLikeDomain)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // Curated defaults first — free, offline, and no API key required.
        // Only domains the shipped table doesn't know go to the AI.
        var results = new List<(string, string)>();
        var unknown = new List<string>();
        foreach (var d in cleaned)
        {
            var curated = Core.DomainCategories.Lookup(d);
            if (curated.Length != 0)
            {
                _db.SetCategory(d, curated);
                results.Add((d, curated));
            }
            else
            {
                unknown.Add(d);
            }
        }

        if (unknown.Count == 0 || Settings.ApiKey.Length == 0)
        {
            if (results.Count != 0)
            {
                _hosts.OrganizeByCategory(results.ToDictionary(r => r.Item1, r => r.Item2, StringComparer.Ordinal));
                RecordRun($"categorized {results.Count} domains (curated)");
            }
            else if (unknown.Count != 0)
            {
                throw new InvalidOperationException("no DeepSeek API key configured");
            }

            return results;
        }

        var settings = RequireKey();
        var vocabulary = preferredCategories is { Count: > 0 }
            ? "Existing hosts-file sections you should reuse whenever they fit: "
              + string.Join(", ", preferredCategories.Select(c => $"\"{c}\"")) + ".\n"
            : string.Empty;

        foreach (var batch in unknown
                     .Take(MaxDomainsPerRun)
                     .Chunk(BatchSize))
        {
            var user = vocabulary + "Categorize these domains:\n" + string.Join('\n', batch);
            var reply = await _completer.CompleteAsync(settings, SystemPrompt, user, ct);
            foreach (var (domain, category) in ParseReply(reply, batch))
            {
                _db.SetCategory(domain, category);
                _db.UpsertAiKnowledge("category", domain, category, settings.Model);
                results.Add((domain, category));
            }
        }

        if (results.Count != 0)
        {
            _hosts.OrganizeByCategory(results.ToDictionary(r => r.Item1, r => r.Item2, StringComparer.Ordinal));
            RecordRun($"categorized {results.Count} domains");
        }

        return results;
    }

    /// <summary>
    /// Categorize every hosts-FILE entry lacking a category (managed or not),
    /// reusing the file's existing "# Section" names as preferred vocabulary.
    /// Unmanaged entries gain a DB row so their category persists.
    /// </summary>
    public async Task<IReadOnlyList<(string Domain, string Category)>> CategorizeHostsFileAsync(CancellationToken ct)
    {
        var categorized = _db.GetDomains()
            .Where(r => !string.IsNullOrEmpty(r.Category))
            .Select(r => r.Domain)
            .ToHashSet(StringComparer.Ordinal);
        var managed = _db.GetDomains().Select(r => r.Domain).ToHashSet(StringComparer.Ordinal);
        var targets = _hosts.GetBlocked().Where(d => !categorized.Contains(d)).ToList();

        // Adopt unmanaged hosts entries so their categories have a home.
        foreach (var d in targets.Where(d => !managed.Contains(d)))
        {
            _db.AddDomain(d, "blocked", "hosts_file");
        }

        var sections = _hosts.GetLines()
            .Where(l => l.TrimStart().StartsWith('#'))
            .Select(l => l.TrimStart('#', ' ', '\t').Trim())
            .Where(s => s.Length is > 0 and <= 40)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(40)
            .ToList();

        return await CategorizeAsync(targets, ct, sections);
    }

    /// <summary>
    /// AI-research purpose descriptions ("what is this domain for") and record
    /// them in the knowledge store (kind=purpose). Returns the resolved pairs.
    /// </summary>
    public async Task<IReadOnlyList<(string Domain, string Purpose)>> ResearchPurposesAsync(
        IReadOnlyList<string> domains, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(domains);
        var settings = RequireKey();
        var results = new List<(string, string)>();
        foreach (var batch in domains
                     .Select(d => d.ToLowerInvariant().Trim())
                     .Where(Core.Domains.LooksLikeDomain)
                     .Distinct(StringComparer.Ordinal)
                     .Take(MaxDomainsPerRun)
                     .Chunk(BatchSize))
        {
            var user = "Describe the purpose of these domains:\n" + string.Join('\n', batch);
            var reply = await _completer.CompleteAsync(settings, PurposePrompt, user, ct);
            foreach (var (domain, purpose) in ParseReply(reply, batch))
            {
                if (!purpose.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    _db.UpsertAiKnowledge("purpose", domain, purpose, settings.Model);
                    results.Add((domain, purpose));
                }
            }
        }

        if (results.Count != 0)
        {
            RecordRun($"researched {results.Count} purposes");
        }

        return results;
    }

    /// <summary>
    /// AI-identify live connections (process + host/IP + port → what it's for)
    /// and record them in the knowledge store (kind=connection, key=host|ip).
    /// </summary>
    public async Task<IReadOnlyList<(string Key, string Info)>> IdentifyConnectionsAsync(
        IReadOnlyList<(string RemoteAddr, string Host, string Process, int Port)> items, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(items);
        var settings = RequireKey();
        var results = new List<(string, string)>();
        var distinct = items
            .Select(i => (Key: (i.Host.Length != 0 ? i.Host : i.RemoteAddr).ToLowerInvariant(), i.RemoteAddr, i.Host, i.Process, i.Port))
            .Where(i => i.Key.Length != 0)
            .DistinctBy(i => i.Key, StringComparer.Ordinal)
            .Take(MaxDomainsPerRun)
            .ToList();
        foreach (var batch in distinct.Chunk(40))
        {
            var lines = batch.Select(i =>
                $"{i.Key} | process={i.Process} host={(i.Host.Length != 0 ? i.Host : "?")} ip={i.RemoteAddr} port={i.Port}");
            var user = "Explain these connections (answer keyed by the first field of each line):\n" + string.Join('\n', lines);
            var reply = await _completer.CompleteAsync(settings, IdentifyPrompt, user, ct);
            foreach (var (key, info) in ParseReply(reply, batch.Select(i => i.Key).ToList()))
            {
                if (!info.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                {
                    _db.UpsertAiKnowledge("connection", key, info, settings.Model);
                    results.Add((key, info));
                }
            }
        }

        if (results.Count != 0)
        {
            RecordRun($"identified {results.Count} connections");
        }

        return results;
    }

    private AiSettings RequireKey()
    {
        var settings = Settings;
        if (settings.ApiKey.Length == 0)
        {
            throw new InvalidOperationException("no DeepSeek API key configured");
        }

        return settings;
    }

    private void RecordRun(string result)
    {
        _db.SetMeta("ai_last_run", DateTime.Now.ToString("o", CultureInfo.InvariantCulture));
        _db.SetMeta("ai_last_result", result);
        _db.LogEvent("ai", "ai_run", details: result);
    }

    /// <summary>Parse the model's JSON reply, keeping only requested domains with sane categories.</summary>
    public static IReadOnlyList<(string Domain, string Category)> ParseReply(string reply, IReadOnlyList<string> requested)
    {
        ArgumentNullException.ThrowIfNull(requested);
        var wanted = new HashSet<string>(requested, StringComparer.Ordinal);
        var results = new List<(string, string)>();
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(reply ?? string.Empty);
        }
        catch (JsonException)
        {
            return results;
        }

        if (node is not JsonObject obj)
        {
            return results;
        }

        foreach (var (key, value) in obj)
        {
            var domain = key.ToLowerInvariant().Trim();
            var category = (value?.GetValueKind() == JsonValueKind.String ? value.GetValue<string>() : string.Empty).Trim();
            if (wanted.Contains(domain) && category.Length is > 0 and <= 60 && !category.Contains('\n'))
            {
                results.Add((domain, category));
            }
        }

        return results;
    }

    private static string NonEmpty(string? value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
}
