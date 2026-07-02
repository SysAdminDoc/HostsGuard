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
            list.Sources.Add(new BlocklistSource
            {
                Category = src.Category,
                Name = src.Name,
                Url = src.Url,
                Subscribed = subscribed,
                LastRefresh = subscribed ? sub.LastRefresh : string.Empty,
                DomainCount = subscribed ? sub.DomainCount : 0,
                LargeListWarning = BlocklistCatalog.LargeLists.Contains(src.Name),
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
            });
        }

        return Task.FromResult(list);
    }

    public override async Task<BlocklistResult> ImportBlocklist(BlocklistRequest request, ServerCallContext context)
    {
        if (_state.Lists is not { } lists)
        {
            return ListsUnavailable();
        }

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

        try
        {
            var outcome = await lists.ImportBlocklistAsync(name, url, context.CancellationToken);
            return new BlocklistResult
            {
                Ok = true,
                Message = $"imported {name}: {outcome.Added} new of {outcome.Total} domains",
                Added = outcome.Added,
                Total = outcome.Total,
                HostsEntries = outcome.HostsEntries,
                Warning = outcome.Warning,
            };
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

    public override Task<Ack> RemoveBlocklistSubscription(BlocklistRequest request, ServerCallContext context)
    {
        _state.Db.RemoveBlocklistSub((request.Name ?? string.Empty).Trim());
        return Task.FromResult(new Ack { Ok = true, Message = $"unsubscribed {request.Name}" });
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
            return new BlocklistResult
            {
                Ok = true,
                Message = $"refreshed subscriptions: {outcome.Added} new of {outcome.Total} domains",
                Added = outcome.Added,
                Total = outcome.Total,
                HostsEntries = outcome.HostsEntries,
                Warning = outcome.Warning,
            };
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

    private static BlocklistResult ListsUnavailable() => new()
    {
        Ok = false,
        Message = "list engine unavailable",
        ErrorCode = "hostsguard.error.v1/lists_unavailable",
    };
}
