using System.Net.Http;
using System.Runtime.Versioning;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>Implements the ListControl gRPC service on the import engine.</summary>
[SupportedOSPlatform("windows")]
public sealed class ListControlServiceImpl : ListControl.ListControlBase
{
    private readonly ServiceState _state;

    public ListControlServiceImpl(ServiceState state) => _state = state;

    public override Task<BlocklistSources> ListBlocklistSources(Empty request, ServerCallContext context)
    {
        var subs = _state.Db.GetBlocklistSubs().ToDictionary(s => s.Name, StringComparer.Ordinal);
        var list = new BlocklistSources();
        foreach (var src in BlocklistCatalog.Sources)
        {
            var subscribed = subs.TryGetValue(src.Name, out var sub);
            var lastRefresh = subscribed && sub is not null ? sub.LastRefresh : string.Empty;
            var domainCount = subscribed && sub is not null ? sub.DomainCount : 0;
            var enabled = !subscribed || sub is null || sub.Enabled;
            var owned = subscribed && sub is not null ? sub.OwnedDomainCount : 0;
            list.Sources.Add(new BlocklistSource
            {
                Category = src.Category,
                Name = src.Name,
                Url = src.Url,
                Subscribed = subscribed,
                LastRefresh = lastRefresh,
                DomainCount = domainCount,
                LargeListWarning = BlocklistCatalog.LargeLists.Contains(src.Name),
                Mirror = src.Mirror,
                Enabled = enabled,
                OwnedDomainCount = owned,
            });
        }

        // Custom (non-catalog) subscriptions surface too.
        foreach (var sub in subs.Values.Where(s => BlocklistCatalog.Sources.All(c => c.Name != s.Name)))
        {
            list.Sources.Add(new BlocklistSource
            {
                Category = "Custom",
                Name = sub.Name,
                Url = sub.Url,
                Subscribed = true,
                LastRefresh = sub.LastRefresh,
                DomainCount = sub.DomainCount,
                Enabled = sub.Enabled,
                OwnedDomainCount = sub.OwnedDomainCount,
            });
        }

        return Task.FromResult(list);
    }

    public override async Task<BlocklistResult> PreviewBlocklist(BlocklistRequest request, ServerCallContext context)
    {
        if (_state.Lists is not { } lists)
        {
            return ListsUnavailable();
        }

        var validation = ValidateBlocklistRequest(request);
        if (validation is not null)
        {
            return validation;
        }

        try
        {
            var outcome = await lists.PreviewBlocklistAsync(request.Name.Trim(), request.Url.Trim(), context.CancellationToken);
            return ToResult(outcome, $"previewed {request.Name}: {outcome.Added} would be new of {outcome.Total} domains");
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return new BlocklistResult
            {
                Ok = false,
                Message = $"preview failed: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/import_failed",
            };
        }
    }

    public override async Task<BlocklistResult> ImportBlocklist(BlocklistRequest request, ServerCallContext context)
    {
        if (_state.Lists is not { } lists)
        {
            return ListsUnavailable();
        }

        var validation = ValidateBlocklistRequest(request);
        if (validation is not null)
        {
            return validation;
        }

        try
        {
            var name = request.Name.Trim();
            var url = request.Url.Trim();
            var outcome = await lists.ImportBlocklistAsync(name, url, context.CancellationToken);
            return ToResult(outcome, $"imported {name}: {outcome.Added} new of {outcome.Total} domains" +
                                     (outcome.MirrorUsed ? " (via mirror)" : string.Empty));
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return new BlocklistResult
            {
                Ok = false,
                Message = $"import failed: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/import_failed",
            };
        }
    }

    public override Task<Ack> SetBlocklistEnabled(BlocklistToggleRequest request, ServerCallContext context)
    {
        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "blocklist name is required",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            });
        }

        _state.Db.SetBlocklistSubEnabled(name, request.Enabled);
        _state.Db.LogEvent($"list:{name}", request.Enabled ? "blocklist_enabled" : "blocklist_disabled", reason: "blocklist");
        return Task.FromResult(new Ack { Ok = true, Message = $"{(request.Enabled ? "enabled" : "disabled")} {name}" });
    }

    public override Task<Ack> RemoveBlocklistSubscription(BlocklistRequest request, ServerCallContext context)
    {
        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "blocklist name is required",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            });
        }

        if (_state.Lists is not { } lists)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "list engine unavailable",
                ErrorCode = "hostsguard.error.v1/lists_unavailable",
            });
        }

        var outcome = lists.RemoveSource(name);
        return Task.FromResult(new Ack
        {
            Ok = true,
            Message = $"removed {name}: deleted {outcome.Removed} source-owned domains, preserved {outcome.Preserved}",
        });
    }

    public override async Task<BlocklistResult> RefreshBlocklists(Empty request, ServerCallContext context)
    {
        if (_state.Lists is not { } lists)
        {
            return ListsUnavailable();
        }

        try
        {
            var outcome = await lists.RefreshAllAsync(context.CancellationToken);
            return ToResult(outcome, $"refreshed subscriptions: {outcome.Added} new of {outcome.Total} domains");
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return new BlocklistResult
            {
                Ok = false,
                Message = $"refresh failed: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/import_failed",
            };
        }
    }

    public override Task<AllowlistUrls> GetAllowlists(Empty request, ServerCallContext context)
    {
        var urls = new AllowlistUrls();
        urls.Urls.AddRange(_state.Db.GetAllowlistSubs());
        return Task.FromResult(urls);
    }

    public override Task<Ack> SetAllowlists(AllowlistUrls request, ServerCallContext context)
    {
        var urls = request.Urls.Select(u => u.Trim()).Where(u => u.Length != 0).ToList();
        if (urls.Any(u => !Uri.TryCreate(u, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps))
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "allowlist URLs must be https://",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            });
        }

        _state.Db.SetAllowlistSubs(urls);
        return Task.FromResult(new Ack { Ok = true, Message = $"saved {urls.Count} allowlist URLs" });
    }

    public override async Task<Ack> RefreshAllowlists(Empty request, ServerCallContext context)
    {
        if (_state.Lists is not { } lists)
        {
            return new Ack { Ok = false, Message = "list engine unavailable", ErrorCode = "hostsguard.error.v1/lists_unavailable" };
        }

        try
        {
            var count = await lists.RefreshAllowlistsAsync(context.CancellationToken);
            return new Ack { Ok = true, Message = $"whitelisted {count} domains from allowlists" };
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return new Ack { Ok = false, Message = $"refresh failed: {ex.Message}", ErrorCode = "hostsguard.error.v1/import_failed" };
        }
    }

    public override async Task<Ack> RefreshThreatIntel(Empty request, ServerCallContext context)
    {
        if (_state.ListFetcher is not { } fetcher)
        {
            return new Ack { Ok = false, Message = "list engine unavailable", ErrorCode = "hostsguard.error.v1/lists_unavailable" };
        }

        try
        {
            var count = await _state.Threats.RefreshAsync(fetcher, context.CancellationToken);
            _state.Db.LogEvent("threat-intel", "refreshed", details: $"{count} IPs");
            return new Ack { Ok = true, Message = $"threat intel refreshed: {count} IPs" };
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return new Ack { Ok = false, Message = $"refresh failed: {ex.Message}", ErrorCode = "hostsguard.error.v1/import_failed" };
        }
    }

    public override async Task<Ack> RefreshGeoIp(Empty request, ServerCallContext context)
    {
        if (_state.ListFetcher is not { } fetcher)
        {
            return new Ack { Ok = false, Message = "list engine unavailable", ErrorCode = "hostsguard.error.v1/lists_unavailable" };
        }

        try
        {
            await _state.GeoIp.RefreshAsync(fetcher, url: null, context.CancellationToken);
            _state.Db.LogEvent("geoip", "refreshed");
            return new Ack { Ok = true, Message = "GeoIP database refreshed" };
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return new Ack { Ok = false, Message = $"refresh failed: {ex.Message}", ErrorCode = "hostsguard.error.v1/import_failed" };
        }
    }

    // ─── Blocklist intelligence (reference index, not active blocks) ─────────

    public override Task<BlocklistIntelStatus> GetBlocklistIntelligence(Empty request, ServerCallContext context)
    {
        var (lists, rows) = _state.Db.GetListIndexStats();
        return Task.FromResult(new BlocklistIntelStatus
        {
            Lists = lists,
            Domains = rows,
            Refreshed = _state.Intel?.LastRefreshed ?? string.Empty,
            Refreshing = _state.Intel?.IsRefreshing ?? false,
        });
    }

    public override async Task<Ack> RefreshBlocklistIntelligence(Empty request, ServerCallContext context)
    {
        if (_state.Intel is not { } intel)
        {
            return new Ack { Ok = false, Message = "list engine unavailable", ErrorCode = "hostsguard.error.v1/lists_unavailable" };
        }

        if (intel.IsRefreshing)
        {
            return new Ack { Ok = true, Message = "intelligence refresh already running" };
        }

        var (indexed, failed) = await intel.RefreshAsync(context.CancellationToken);
        var (lists, rows) = _state.Db.GetListIndexStats();
        return new Ack
        {
            Ok = indexed > 0,
            Message = indexed > 0
                ? $"indexed {indexed} lists ({rows:N0} domains total{(failed > 0 ? $", {failed} failed" : string.Empty)})"
                : "no lists could be downloaded — check connectivity and retry",
            ErrorCode = indexed > 0 ? string.Empty : "hostsguard.error.v1/intel_failed",
        };
    }

    private static BlocklistResult ListsUnavailable() => new()
    {
        Ok = false,
        Message = "list engine unavailable",
        ErrorCode = "hostsguard.error.v1/lists_unavailable",
    };

    private static BlocklistResult? ValidateBlocklistRequest(BlocklistRequest request)
    {
        var name = (request.Name ?? string.Empty).Trim();
        var url = (request.Url ?? string.Empty).Trim();
        if (name.Length == 0 || !Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return new BlocklistResult
            {
                Ok = false,
                Message = "a name and an https:// URL are required",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            };
        }

        return null;
    }

    private static BlocklistResult ToResult(ImportOutcome outcome, string message) => new()
    {
        Ok = true,
        Message = message,
        Added = outcome.Added,
        Total = outcome.Total,
        HostsEntries = outcome.HostsEntries,
        Warning = outcome.Warning,
        Duplicates = outcome.Duplicates,
        Invalid = outcome.Invalid,
        HijackFlagged = outcome.HijackFlagged,
        AllowlistOverrides = outcome.AllowlistOverrides,
        MirrorUsed = outcome.MirrorUsed,
        Removed = outcome.Removed,
        Preserved = outcome.Preserved,
        Preview = outcome.Preview,
    };
}
