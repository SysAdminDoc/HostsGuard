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
            var hits30d = subscribed && sub is not null ? sub.Hits30d : 0;
            list.Sources.Add(new BlocklistSource
            {
                Category = src.Category,
                Name = src.Name,
                Url = src.Url,
                Homepage = src.Homepage,
                License = src.License,
                Tags = src.Tags,
                Description = src.Description,
                Subscribed = subscribed,
                LastRefresh = lastRefresh,
                DomainCount = domainCount,
                LargeListWarning = BlocklistCatalog.LargeLists.Contains(src.Name),
                Mirror = src.Mirror,
                Enabled = enabled,
                OwnedDomainCount = owned,
                Hits30D = hits30d,
                HealthStatus = subscribed && sub is not null ? sub.HealthStatus : "new",
                ContentHash = subscribed && sub is not null ? sub.ContentHash : string.Empty,
                PreviousHash = subscribed && sub is not null ? sub.PreviousHash : string.Empty,
                PreviousDomainCount = subscribed && sub is not null ? sub.PreviousDomainCount : 0,
                LastError = subscribed && sub is not null ? sub.LastError : string.Empty,
                LastErrorAt = subscribed && sub is not null ? sub.LastErrorAt : string.Empty,
                RollbackCheckpointId = subscribed && sub is not null ? sub.LastCheckpointId : 0,
                LastAttemptHash = subscribed && sub is not null ? sub.LastAttemptHash : string.Empty,
                LastAttemptDomainCount = subscribed && sub is not null ? sub.LastAttemptDomainCount : 0,
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
                Hits30D = sub.Hits30d,
                HealthStatus = sub.HealthStatus,
                ContentHash = sub.ContentHash,
                PreviousHash = sub.PreviousHash,
                PreviousDomainCount = sub.PreviousDomainCount,
                LastError = sub.LastError,
                LastErrorAt = sub.LastErrorAt,
                RollbackCheckpointId = sub.LastCheckpointId,
                LastAttemptHash = sub.LastAttemptHash,
                LastAttemptDomainCount = sub.LastAttemptDomainCount,
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
            var suffix = (outcome.Guarded, outcome.Failed) switch
            {
                (0, 0) => string.Empty,
                (_, 0) => $"; {outcome.Guarded} guarded",
                (0, _) => $"; {outcome.Failed} failed",
                _ => $"; {outcome.Guarded} guarded, {outcome.Failed} failed",
            };
            return ToResult(
                outcome,
                $"refreshed subscriptions: {outcome.Added} new of {outcome.Total} domains{suffix}",
                ok: outcome.Guarded == 0 && outcome.Failed == 0,
                errorCode: outcome.Guarded != 0 ? "hostsguard.error.v1/churn_guarded"
                    : outcome.Failed != 0 ? "hostsguard.error.v1/import_failed" : string.Empty);
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

    public override Task<Ack> RestoreBlocklistCheckpoint(BlocklistRequest request, ServerCallContext context)
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

        try
        {
            var outcome = lists.RestoreCheckpoint(name);
            return Task.FromResult(new Ack
            {
                Ok = true,
                Message = $"restored {name} checkpoint {outcome.CheckpointId}: restored {outcome.Total}, removed {outcome.Removed}, preserved {outcome.Preserved}",
            });
        }
        catch (InvalidOperationException ex)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = ex.Message,
                ErrorCode = "hostsguard.error.v1/no_checkpoint",
            });
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

    // ─── IP-format blocklists → HG_IPBlock_* firewall rules (NET-171) ────────

    public override Task<IpBlocklistList> ListIpBlocklists(Empty request, ServerCallContext context)
    {
        var list = new IpBlocklistList();
        foreach (var row in _state.Db.GetIpBlocklistSources())
        {
            list.Sources.Add(new IpBlocklistSource
            {
                Name = row.Name,
                Url = row.Url,
                Enabled = row.Enabled,
                AddressCount = row.AddressCount,
                RuleCount = row.RuleCount,
                HealthStatus = row.HealthStatus,
                ContentHash = row.ContentHash,
                PreviousHash = row.PreviousHash,
                PreviousAddressCount = row.PreviousAddressCount,
                LastError = row.LastError,
                LastErrorAt = row.LastErrorAt,
                LastRefresh = row.LastRefresh,
                Truncated = row.Truncated,
            });
        }

        return Task.FromResult(list);
    }

    public override async Task<IpBlocklistResult> ImportIpBlocklist(BlocklistRequest request, ServerCallContext context)
    {
        if (_state.IpBlocklists is not { } coordinator)
        {
            return IpListsUnavailable();
        }

        var name = (request.Name ?? string.Empty).Trim();
        var url = (request.Url ?? string.Empty).Trim();
        if (name.Length == 0 || !Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return new IpBlocklistResult
            {
                Ok = false,
                Message = "a name and an https:// URL are required",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            };
        }

        try
        {
            var outcome = await coordinator.ImportAsync(name, url, context.CancellationToken);
            return ToIpResult(outcome,
                $"imported {name}: {outcome.Total:N0} addresses across {outcome.Rules} firewall rules");
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return new IpBlocklistResult
            {
                Ok = false,
                Message = $"import failed: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/import_failed",
            };
        }
    }

    public override Task<Ack> SetIpBlocklistEnabled(BlocklistToggleRequest request, ServerCallContext context)
    {
        if (_state.IpBlocklists is not { } coordinator)
        {
            return Task.FromResult(new Ack { Ok = false, Message = "list engine unavailable", ErrorCode = "hostsguard.error.v1/lists_unavailable" });
        }

        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return Task.FromResult(new Ack { Ok = false, Message = "IP blocklist name is required", ErrorCode = "hostsguard.error.v1/invalid_source" });
        }

        return Task.FromResult(coordinator.SetEnabled(name, request.Enabled));
    }

    public override Task<Ack> RemoveIpBlocklist(BlocklistRequest request, ServerCallContext context)
    {
        if (_state.IpBlocklists is not { } coordinator)
        {
            return Task.FromResult(new Ack { Ok = false, Message = "list engine unavailable", ErrorCode = "hostsguard.error.v1/lists_unavailable" });
        }

        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return Task.FromResult(new Ack { Ok = false, Message = "IP blocklist name is required", ErrorCode = "hostsguard.error.v1/invalid_source" });
        }

        return Task.FromResult(coordinator.Remove(name));
    }

    public override async Task<IpBlocklistResult> RefreshIpBlocklists(Empty request, ServerCallContext context)
    {
        if (_state.IpBlocklists is not { } coordinator)
        {
            return IpListsUnavailable();
        }

        try
        {
            var outcome = await coordinator.RefreshAllAsync(context.CancellationToken);
            var suffix = (outcome.Guarded, outcome.Failed) switch
            {
                (0, 0) => string.Empty,
                (_, 0) => $"; {outcome.Guarded} guarded",
                (0, _) => $"; {outcome.Failed} failed",
                _ => $"; {outcome.Guarded} guarded, {outcome.Failed} failed",
            };
            return ToIpResult(outcome,
                $"refreshed IP blocklists: {outcome.Total:N0} addresses across {outcome.Rules} rules{suffix}",
                ok: outcome.Guarded == 0 && outcome.Failed == 0,
                errorCode: outcome.Guarded != 0 ? "hostsguard.error.v1/churn_guarded"
                    : outcome.Failed != 0 ? "hostsguard.error.v1/import_failed" : string.Empty);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            return new IpBlocklistResult
            {
                Ok = false,
                Message = $"refresh failed: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/import_failed",
            };
        }
    }

    public override Task<IpBlocklistResult> RollbackIpBlocklist(BlocklistRequest request, ServerCallContext context)
    {
        if (_state.IpBlocklists is not { } coordinator)
        {
            return Task.FromResult(IpListsUnavailable());
        }

        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return Task.FromResult(new IpBlocklistResult
            {
                Ok = false,
                Message = "IP blocklist name is required",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            });
        }

        try
        {
            var outcome = coordinator.Rollback(name);
            return Task.FromResult(ToIpResult(outcome,
                $"rolled back {name}: {outcome.Total:N0} addresses across {outcome.Rules} rules"));
        }
        catch (InvalidOperationException ex)
        {
            return Task.FromResult(new IpBlocklistResult
            {
                Ok = false,
                Message = ex.Message,
                ErrorCode = "hostsguard.error.v1/no_checkpoint",
            });
        }
    }

    private static IpBlocklistResult IpListsUnavailable() => new()
    {
        Ok = false,
        Message = "list engine unavailable",
        ErrorCode = "hostsguard.error.v1/lists_unavailable",
    };

    private static IpBlocklistResult ToIpResult(
        IpImportOutcome outcome,
        string message,
        bool ok = true,
        string errorCode = "") => new()
    {
        Ok = ok,
        Message = message,
        ErrorCode = errorCode,
        Total = outcome.Total,
        Invalid = outcome.Invalid,
        Duplicates = outcome.Duplicates,
        Unsafe = outcome.Unsafe,
        Rules = outcome.Rules,
        Truncated = outcome.Truncated,
        Guarded = outcome.Guarded,
        Failed = outcome.Failed,
        Warning = outcome.Warning,
    };

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

    private static BlocklistResult ToResult(
        ImportOutcome outcome,
        string message,
        bool ok = true,
        string errorCode = "") => new()
    {
        Ok = ok,
        Message = message,
        ErrorCode = errorCode,
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
        Guarded = outcome.Guarded,
        Failed = outcome.Failed,
        CheckpointId = outcome.CheckpointId,
        ModifiersStripped = outcome.ModifiersStripped,
    };
}
