using System.Net.Http;
using System.Runtime.Versioning;
using System.Text;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;

namespace HostsGuard.Service;

/// <summary>Implements the ListControl gRPC service on the import engine.</summary>
[SupportedOSPlatform("windows")]
public sealed class ListControlServiceImpl : ListControl.ListControlBase
{
    private const int MaxMirrors = 5;
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
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
            var mirrors = EffectiveMirrors(src, sub);
            var item = new BlocklistSource
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
                Mirror = mirrors.FirstOrDefault() ?? string.Empty,
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
                LastEndpoint = subscribed && sub is not null ? sub.LastEndpoint : string.Empty,
                LastEndpointLatencyMs = subscribed && sub is not null ? sub.LastEndpointLatencyMs : 0,
            };
            item.Mirrors.AddRange(mirrors);
            list.Sources.Add(item);
        }

        // Custom (non-catalog) subscriptions surface too.
        foreach (var sub in subs.Values.Where(s => BlocklistCatalog.Sources.All(c => c.Name != s.Name)))
        {
            var item = new BlocklistSource
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
                Mirror = sub.Mirrors.FirstOrDefault() ?? string.Empty,
                LastEndpoint = sub.LastEndpoint,
                LastEndpointLatencyMs = sub.LastEndpointLatencyMs,
            };
            item.Mirrors.AddRange(sub.Mirrors);
            list.Sources.Add(item);
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

        if (await ValidateMirrorTargetsAsync(request.Mirrors, context.CancellationToken) is { } mirrorError)
        {
            return mirrorError;
        }

        try
        {
            var outcome = await lists.PreviewBlocklistAsync(
                request.Name.Trim(), request.Url.Trim(), context.CancellationToken, request.Mirrors.ToArray());
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

        if (await ValidateMirrorTargetsAsync(request.Mirrors, context.CancellationToken) is { } mirrorError)
        {
            return mirrorError;
        }

        try
        {
            var name = request.Name.Trim();
            var url = request.Url.Trim();
            var outcome = await lists.ImportBlocklistAsync(name, url, context.CancellationToken, request.Mirrors.ToArray());
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

    public override async Task<BlocklistResult> PreviewBlocklistContent(BlocklistContentRequest request, ServerCallContext context)
    {
        if (_state.Lists is not { } lists)
        {
            return ListsUnavailable();
        }

        var (name, content, error) = ValidateContentRequest(request);
        if (error is not null)
        {
            return error;
        }

        var outcome = await lists.PreviewBlocklistContentAsync(name, content, context.CancellationToken);
        return ToResult(outcome, $"previewed {name}: {outcome.Added} would be new of {outcome.Total} domains from local content");
    }

    public override async Task<BlocklistResult> ImportBlocklistContent(BlocklistContentRequest request, ServerCallContext context)
    {
        if (_state.Lists is not { } lists)
        {
            return ListsUnavailable();
        }

        var (name, content, error) = ValidateContentRequest(request);
        if (error is not null)
        {
            return error;
        }

        var outcome = await lists.ImportBlocklistContentAsync(name, content, context.CancellationToken);
        return ToResult(outcome, $"imported {name}: {outcome.Added} new of {outcome.Total} domains from local content");
    }

    /// <summary>
    /// Validate a local-content import: a non-empty name, non-empty content, and a
    /// hard byte cap so the unelevated client can never stream an unbounded payload
    /// into the LocalSystem service. Returns the decoded UTF-8 text or an error.
    /// </summary>
    private static (string Name, string Content, BlocklistResult? Error) ValidateContentRequest(BlocklistContentRequest request)
    {
        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return (name, string.Empty, new BlocklistResult
            {
                Ok = false,
                Message = "blocklist name is required",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            });
        }

        var bytes = request.Content;
        if (bytes is null || bytes.Length == 0)
        {
            return (name, string.Empty, new BlocklistResult
            {
                Ok = false,
                Message = "list content is empty",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            });
        }

        if (bytes.Length > BlocklistCatalog.MaxBlocklistBytes)
        {
            return (name, string.Empty, new BlocklistResult
            {
                Ok = false,
                Message = $"list content exceeds the {BlocklistCatalog.MaxBlocklistBytes / 1_000_000} MB import cap",
                ErrorCode = "hostsguard.error.v1/content_too_large",
            });
        }

        try
        {
            var content = StrictUtf8.GetString(bytes.Span);
            return (name, content.Length > 0 && content[0] == '\uFEFF' ? content[1..] : content, null);
        }
        catch (DecoderFallbackException)
        {
            return (name, string.Empty, new BlocklistResult
            {
                Ok = false,
                Message = "list content is not valid UTF-8",
                ErrorCode = "hostsguard.error.v1/invalid_encoding",
            });
        }
    }

    public override Task<Ack> SetBlocklistEnabled(BlocklistToggleRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("ListControl") is { } gate) return Task.FromResult(gate);

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

    public override async Task<Ack> SetBlocklistMirrors(BlocklistMirrorsRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("ListControl") is { } gate) return gate;

        var name = (request.Name ?? string.Empty).Trim();
        var mirrors = NormalizeMirrors(request.Mirrors);
        if (name.Length == 0 || mirrors is null)
        {
            return new Ack
            {
                Ok = false,
                Message = $"a blocklist name and up to {MaxMirrors} distinct https:// mirrors are required",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            };
        }

        if (_state.Db.GetBlocklistSub(name) is null)
        {
            return new Ack { Ok = false, Message = $"blocklist '{name}' was not found", ErrorCode = "hostsguard.error.v1/not_found" };
        }

        try
        {
            foreach (var mirror in mirrors)
            {
                await SsrfGuard.EnsurePublicHttpsAsync(mirror, context.CancellationToken);
            }
        }
        catch (SsrfBlockedException ex)
        {
            return new Ack { Ok = false, Message = ex.Message, ErrorCode = "hostsguard.error.v1/invalid_source" };
        }

        _state.Db.SetBlocklistMirrors(name, mirrors);
        _state.Db.LogEvent($"list:{name}", "blocklist_mirrors_updated",
            details: $"{mirrors.Count} ordered fallback{(mirrors.Count == 1 ? string.Empty : "s")}", reason: "blocklist");
        return new Ack { Ok = true, Message = $"saved {mirrors.Count} fallback mirror{(mirrors.Count == 1 ? string.Empty : "s")} for {name}" };
    }

    public override Task<Ack> RemoveBlocklistSubscription(BlocklistRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("ListControl") is { } gate) return Task.FromResult(gate);

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
        if (_state.GateWhenLocked("ListControl") is { } gate)
        {
            return new BlocklistResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode };
        }

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

    public override Task<WindowsConnectivityRecoveryResult> RecoverWindowsConnectivity(
        WindowsConnectivityRecoveryRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("ListControl") is { } gate)
        {
            return Task.FromResult(new WindowsConnectivityRecoveryResult
            {
                Ok = false,
                Message = gate.Message,
                ErrorCode = gate.ErrorCode,
            });
        }

        var requested = request.Domains.Select(Domains.ToAscii)
            .Where(static domain => domain.Length != 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var candidates = requested.Length == 0
            ? _state.Db.GetDomains(status: "blocked")
                .Where(static row => (row.Source ?? string.Empty).StartsWith("list:", StringComparison.Ordinal))
                .Select(static row => row.Domain)
                .Where(static domain => WindowsConnectivityChecks.TryGet(domain, out _))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray()
            : requested;
        var rejected = candidates.Where(domain =>
                !WindowsConnectivityChecks.TryGet(domain, out _) ||
                !string.Equals(_state.Db.GetDomainStatus(domain), "blocked", StringComparison.Ordinal) ||
                !(_state.Db.GetDomainSource(domain) ?? string.Empty).StartsWith("list:", StringComparison.Ordinal))
            .ToArray();
        var recoverable = candidates.Except(rejected, StringComparer.Ordinal).ToArray();
        if (recoverable.Length != 0)
        {
            _state.Db.AddDomainsBulk(recoverable.Select(static domain => (domain, "whitelisted", "ncsi_recovery")));
            _state.Hosts.Reconcile(_state.Db.GetDomains(status: "blocked").Select(static row => row.Domain));
            _state.Db.LogEvent("windows_ncsi", "connectivity_recovered",
                details: $"allowlisted exact list-blocked probes: {string.Join(',', recoverable)}" +
                    (rejected.Length == 0 ? string.Empty : $"; rejected: {string.Join(',', rejected)}"), reason: "blocklist_safety");
        }

        var result = new WindowsConnectivityRecoveryResult
        {
            Ok = recoverable.Length != 0 || candidates.Length == 0,
            ErrorCode = recoverable.Length == 0 && rejected.Length != 0
                ? "hostsguard.error.v1/unsafe_recovery_selection" : string.Empty,
            Message = candidates.Length == 0
                ? "no list-blocked Windows connectivity probes needed recovery"
                : recoverable.Length == 0
                    ? "no selected domains were exact NCSI probes currently blocked by a list source"
                    : $"recovered {recoverable.Length} Windows connectivity probe domain{(recoverable.Length == 1 ? string.Empty : "s")}" +
                      (rejected.Length == 0 ? string.Empty : $"; left {rejected.Length} ineligible selection{(rejected.Length == 1 ? string.Empty : "s")} unchanged"),
        };
        result.RecoveredDomains.AddRange(recoverable);
        result.RejectedDomains.AddRange(rejected);
        return Task.FromResult(result);
    }

    public override Task<Ack> RestoreBlocklistCheckpoint(BlocklistRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("ListControl") is { } gate) return Task.FromResult(gate);

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
        if (_state.GateWhenLocked("ListControl") is { } gate) return Task.FromResult(gate);

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
        if (_state.GateWhenLocked("ListControl") is { } gate) return gate;

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
            var scan = _state.ThreatHistoryRescan.Scan(_state.Clock.Now, context.CancellationToken);
            _state.Db.LogEvent(
                "threat-intel",
                "refreshed",
                details: $"{count} IPs; scanned {scan.ScannedRows} retained rows; raised {scan.AlertsRaised} alerts");
            return new Ack
            {
                Ok = true,
                Message = $"threat intel refreshed: {count} IPs; scanned {scan.ScannedRows} retained connections; {scan.AlertsRaised} new alerts",
            };
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

            // ASN attribution shares this refresh but is best-effort: a missing or
            // failed ASN database must not fail the country refresh that succeeded.
            var asnNote = string.Empty;
            try
            {
                await _state.Asn.RefreshAsync(fetcher, url: null, context.CancellationToken);
                _state.Db.LogEvent("asn", "refreshed");
                asnNote = " + ASN";
            }
            catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
            {
                _state.Db.LogEvent("asn", "refresh_failed", details: ex.Message);
                asnNote = " (ASN refresh failed)";
            }

            return new Ack { Ok = true, Message = $"GeoIP database refreshed{asnNote}" };
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
        if (_state.GateWhenLocked("ListControl") is { } gate) return Task.FromResult(gate);

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
        if (_state.GateWhenLocked("ListControl") is { } gate) return Task.FromResult(gate);

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
        if (_state.GateWhenLocked("ListControl") is { } gate)
        {
            return new IpBlocklistResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode };
        }

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
        if (_state.GateWhenLocked("ListControl") is { } gate)
        {
            return Task.FromResult(new IpBlocklistResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode });
        }

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

        var mirrors = NormalizeMirrors(request.Mirrors);
        if (mirrors is null || mirrors.Any(mirror => mirror.Equals(url, StringComparison.Ordinal)))
        {
            return new BlocklistResult
            {
                Ok = false,
                Message = $"mirrors must be up to {MaxMirrors} distinct https:// URLs different from the primary",
                ErrorCode = "hostsguard.error.v1/invalid_source",
            };
        }

        return null;
    }

    private static IReadOnlyList<string>? NormalizeMirrors(IEnumerable<string> values)
    {
        var mirrors = values.Select(static value => (value ?? string.Empty).Trim())
            .Where(static value => value.Length != 0)
            .ToArray();
        if (mirrors.Length > MaxMirrors || mirrors.Distinct(StringComparer.Ordinal).Count() != mirrors.Length)
        {
            return null;
        }

        return mirrors.All(static value =>
                value.Length <= 2048
                && Uri.TryCreate(value, UriKind.Absolute, out var uri)
                && uri.Scheme == Uri.UriSchemeHttps)
            ? mirrors
            : null;
    }

    private static async Task<BlocklistResult?> ValidateMirrorTargetsAsync(
        IEnumerable<string> mirrors,
        CancellationToken cancellationToken)
    {
        try
        {
            foreach (var mirror in mirrors)
            {
                await SsrfGuard.EnsurePublicHttpsAsync(mirror, cancellationToken);
            }

            return null;
        }
        catch (SsrfBlockedException ex)
        {
            return new BlocklistResult
            {
                Ok = false,
                Message = ex.Message,
                ErrorCode = "hostsguard.error.v1/invalid_source",
            };
        }
    }

    private static IReadOnlyList<string> EffectiveMirrors(BlocklistSourceInfo catalog, BlocklistSubRow? sub)
        => (sub?.Mirrors ?? Array.Empty<string>())
            .Append(catalog.Mirror)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    private static BlocklistResult ToResult(
        ImportOutcome outcome,
        string message,
        bool ok = true,
        string errorCode = "")
    {
        var result = new BlocklistResult
        {
            Ok = ok, Message = message, ErrorCode = errorCode, Added = outcome.Added,
            Total = outcome.Total, HostsEntries = outcome.HostsEntries, Warning = outcome.Warning,
            Duplicates = outcome.Duplicates, Invalid = outcome.Invalid, HijackFlagged = outcome.HijackFlagged,
            AllowlistOverrides = outcome.AllowlistOverrides, MirrorUsed = outcome.MirrorUsed,
            Removed = outcome.Removed, Preserved = outcome.Preserved, Preview = outcome.Preview,
            Guarded = outcome.Guarded, Failed = outcome.Failed, CheckpointId = outcome.CheckpointId,
            ModifiersStripped = outcome.ModifiersStripped,
            SelectedEndpoint = outcome.SelectedEndpoint,
            SelectedEndpointLatencyMs = outcome.SelectedEndpointLatencyMs,
        };
        foreach (var warning in outcome.ConnectivityWarnings ?? Array.Empty<Core.WindowsConnectivityWarning>())
        {
            result.ConnectivityWarnings.Add(new Contracts.WindowsConnectivityWarning
            {
                Domain = warning.Dependency.Domain,
                ProbeKind = warning.Dependency.ProbeKind.ToString().ToLowerInvariant(),
                Era = warning.Dependency.Era.ToString().ToLowerInvariant(),
                Reason = warning.Reason,
                Code = Core.WindowsConnectivityWarning.WarningCode,
            });
        }
        return result;
    }
}
