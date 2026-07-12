using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>DNS control: cache flush, resolver switching, and domain inspection.</summary>
[SupportedOSPlatform("windows")]
public sealed class DnsControlServiceImpl : DnsControl.DnsControlBase
{
    private const int DefaultDnsCacheLimit = 500;
    private const int MaxDnsCacheLimit = 2_000;

    private readonly ServiceState _state;

    public DnsControlServiceImpl(ServiceState state) => _state = state;

    public override Task<IdnHomographStatus> GetIdnHomographStatus(Empty request, ServerCallContext context)
        => Task.FromResult(new IdnHomographStatus
        {
            Enabled = _state.IdnHomographs.Enabled,
            CorpusSize = _state.IdnHomographs.CorpusSize,
            Standard = $"Unicode {IdnHomographDetector.UnicodeVersion} / UTS #39",
        });

    public override Task<Ack> SetIdnHomograph(IdnHomographRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        _state.IdnHomographs.SetEnabled(request.Enabled);
        _state.Db.LogEvent("idn_homograph", request.Enabled ? "enabled" : "disabled",
            process: "dns", details: "alert-only IDN homograph detection", reason: "dns_security");
        return Task.FromResult(new Ack
        {
            Ok = true,
            Message = request.Enabled
                ? "IDN homograph detection enabled (alert only; no automatic blocking)"
                : "IDN homograph detection disabled",
        });
    }

    public override Task<Ack> FlushCache(Empty request, ServerCallContext context)
    {
        if (_state.Dns is not { } dns)
        {
            return Task.FromResult(Error("dns_unavailable", "DNS engine is not attached to this service instance"));
        }

        return Task.FromResult(dns.FlushCache()
            ? Ok("DNS cache flushed")
            : Error("flush_failed", "DnsFlushResolverCache refused"));
    }

    public override Task<Ack> FlushCacheEntry(DnsCacheEntryRequest request, ServerCallContext context)
    {
        if (_state.Dns is not { } dns)
        {
            return Task.FromResult(Error("dns_unavailable", "DNS engine is not attached to this service instance"));
        }

        var name = NormalizeCacheEntryName(request.Name);
        if (!IsValidCacheEntryName(name))
        {
            return Task.FromResult(Error("invalid_cache_entry", "DNS cache entry name is empty or invalid"));
        }

        try
        {
            if (!dns.FlushCacheEntry(name))
            {
                return Task.FromResult(Error("cache_entry_flush_failed", $"DNS cache entry was not flushed: {name}"));
            }
        }
        catch (Exception ex) when (IsDnsCacheApiException(ex))
        {
            return Task.FromResult(Error("dns_cache_unavailable", $"Targeted DNS cache flush is unavailable: {ex.GetType().Name}"));
        }

        _state.Db.LogEvent(name, "cache_entry_flush", process: "dns", details: "targeted resolver-cache flush");
        return Task.FromResult(Ok($"DNS cache entry flushed: {name}"));
    }

    public override Task<DnsCacheList> ListCache(DnsCacheRequest request, ServerCallContext context)
    {
        var result = new DnsCacheList();
        if (_state.Dns is not { } dns)
        {
            result.Available = false;
            result.Message = "DNS engine is not attached to this service instance";
            return Task.FromResult(result);
        }

        var limit = request.Limit <= 0 ? DefaultDnsCacheLimit : Math.Clamp(request.Limit, 1, MaxDnsCacheLimit);
        var search = (request.Search ?? string.Empty).Trim();
        try
        {
            foreach (var row in dns.GetCacheEntries(limit, search))
            {
                var serviceBinding = IsServiceBindingType(row.Type);
                result.Entries.Add(new DnsCacheEntry
                {
                    Name = row.Name,
                    Type = row.Type,
                    DataLength = row.DataLength,
                    Flags = row.Flags,
                    ServiceBinding = serviceBinding,
                    PrivacyRole = serviceBinding ? DnsCachePrivacyRole(row) : string.Empty,
                });
            }

            result.Available = true;
            result.Message = $"{result.Entries.Count} DNS cache entries";
            return Task.FromResult(result);
        }
        catch (Exception ex) when (IsDnsCacheApiException(ex))
        {
            result.Available = false;
            result.Message = $"DNS cache listing is unavailable: {ex.GetType().Name}";
            return Task.FromResult(result);
        }
    }

    public override Task<ResolverAdapterList> ListResolverAdapters(Empty request, ServerCallContext context)
    {
        var result = new ResolverAdapterList();
        if (_state.Dns is not { } dns)
        {
            return Task.FromResult(result);
        }

        foreach (var adapter in dns.ListResolverAdapters())
        {
            var item = new ResolverAdapterInfo
            {
                Id = adapter.Id,
                Name = adapter.Name,
                Description = adapter.Description,
                IsUp = adapter.IsUp,
                IsVpn = adapter.IsVpn,
                UsesDhcp = adapter.UsesDhcp,
            };
            item.ConfiguredServers.AddRange(adapter.ConfiguredResolvers);
            item.EffectiveServers.AddRange(adapter.EffectiveResolvers);
            result.Adapters.Add(item);
        }

        return Task.FromResult(result);
    }

    public override async Task<Ack> SetResolver(ResolverRequest request, ServerCallContext context)
    {
        if (_state.Dns is not { } dns)
        {
            return Error("dns_unavailable", "DNS engine is not attached to this service instance");
        }

        var servers = request.Servers.Select(s => s.Trim()).Where(s => s.Length != 0).ToList();
        if (servers.Any(s => !IPAddress.TryParse(s, out _)))
        {
            return Error("invalid_resolver", "resolver list contains a non-IP entry");
        }

        var probeHost = string.IsNullOrWhiteSpace(request.ProbeHost) ? "example.com" : request.ProbeHost.Trim().TrimEnd('.');
        if (!Domains.LooksLikeDomain(probeHost))
        {
            return Error("invalid_probe_host", "resolver probe host must be a valid domain");
        }

        var adapters = dns.ListResolverAdapters();
        var adapterIds = request.AdapterIds.Select(id => id.Trim()).Where(id => id.Length != 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (adapterIds.Count == 0)
        {
            // Compatibility for older clients: retain the prior physical-adapter
            // behavior, but never mutate a VPN/tunnel implicitly.
            adapterIds.AddRange(adapters.Where(adapter => adapter.IsUp && !adapter.IsVpn).Select(adapter => adapter.Id));
        }

        if (adapterIds.Count == 0)
        {
            return Error("no_adapter", "no eligible DNS adapter was selected");
        }

        Windows.DnsResolverChange change;
        try
        {
            change = dns.SetResolvers(servers, adapterIds);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException or IOException)
        {
            _state.Db.LogEvent("dns", "resolver_apply_rollback",
                details: $"{ex.GetType().Name}: {ex.Message}", reason: "transaction");
            return Error("resolver_apply_failed", $"DNS resolver change was not applied: {ex.Message}");
        }

        Windows.DnsProbeResult probe;
        try
        {
            probe = await dns.ProbeAsync(probeHost, TimeSpan.FromSeconds(5), context.CancellationToken);
        }
        catch (OperationCanceledException)
        {
            probe = new Windows.DnsProbeResult(false, TimeSpan.FromSeconds(5), 0, 0, "cancelled");
        }

        if (!probe.Success || probe.Ipv4Count == 0 || probe.Ipv6Count == 0)
        {
            try
            {
                dns.RestoreResolvers(change.Prior);
                _state.Db.LogEvent("dns", "resolver_rollback",
                    details: $"probe {probeHost} failed ({probe.Error}; A={probe.Ipv4Count}, AAAA={probe.Ipv6Count}); restored {change.Prior.Adapters.Count} adapters",
                    reason: "health_probe");
                return Error("resolver_probe_failed",
                    $"DNS probe failed ({probe.Error}; A={probe.Ipv4Count}, AAAA={probe.Ipv6Count}); restored every selected adapter exactly");
            }
            catch (Exception restoreError)
            {
                _state.Db.LogEvent("dns", "resolver_rollback_failed",
                    details: $"{restoreError.GetType().Name}: {restoreError.Message}", reason: "health_probe");
                return Error("resolver_rollback_failed",
                    $"DNS probe failed and exact rollback also failed: {restoreError.Message}");
            }
        }

        var names = string.Join(", ", change.ChangedAdapters.Select(adapter => adapter.Name));
        var prior = string.Join("; ", change.Prior.Adapters.Select(adapter =>
            $"{adapter.Name}={(adapter.UsesDhcp ? "DHCP" : string.Join(",", adapter.ConfiguredResolvers))}"));
        _state.Db.LogEvent("dns", "resolver_switch",
            details: $"{(servers.Count == 0 ? "DHCP" : string.Join(",", servers))}; adapters={names}; prior={prior}; " +
                     $"probe={probeHost} {probe.RoundTrip.TotalMilliseconds:F0}ms A={probe.Ipv4Count} AAAA={probe.Ipv6Count}");
        return Ok($"DNS updated on {names}; {probeHost} A+AAAA probe passed in {probe.RoundTrip.TotalMilliseconds:F0} ms");
    }

    public override async Task<DnsInspectResult> Inspect(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        var result = new DnsInspectResult
        {
            Blocked = _state.Hosts.GetBlocked().Contains(d),
        };
        if (!Domains.LooksLikeDomain(d))
        {
            return result;
        }

        var sw = Stopwatch.StartNew();
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(d, context.CancellationToken);
            sw.Stop();
            result.LatencyMs = (int)sw.ElapsedMilliseconds;
            foreach (var addr in addresses)
            {
                result.Records.Add(new DnsRecord
                {
                    Type = addr.AddressFamily == AddressFamily.InterNetworkV6 ? "AAAA" : "A",
                    Name = d,
                    Value = addr.ToString(),
                });
            }

            if (addresses.Length > 0 && addresses.All(a => IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any)))
            {
                result.Blocked = true;
            }
        }
        catch (SocketException)
        {
            sw.Stop();
            result.LatencyMs = (int)sw.ElapsedMilliseconds;
        }

        var serviceBindings = ServiceBindingCacheRows(MaxDnsCacheLimit, d);
        foreach (var row in serviceBindings)
        {
            result.Records.Add(new DnsRecord
            {
                Type = row.Type,
                Name = row.Name,
                Value = DnsCachePrivacyRole(row),
            });
        }

        var counts = CountServiceBindings(serviceBindings);
        result.HttpsRecords = counts.HttpsRecords;
        result.SvcbRecords = counts.SvcbRecords;
        ApplyPosture(result, BuildPosture(counts));
        return result;
    }

    public override Task<DohStatus> GetDohStatus(Empty request, ServerCallContext context)
    {
        var state = _state.Doh.Load();
        var extras = Core.DohResolvers.NormalizeIpSet(state.Ips);
        extras.ExceptWith(Core.DohResolvers.NormalizeIpSet(Core.DohResolvers.BuiltIn));
        var counts = CountServiceBindings(ServiceBindingCacheRows(MaxDnsCacheLimit, null));
        var posture = BuildPosture(counts);
        return Task.FromResult(new DohStatus
        {
            ResolverIps = _state.Doh.CurrentIps().Count,
            ExtraIps = extras.Count,
            Updated = state.Updated,
            Source = state.Source,
            Sha256 = state.Sha256,
            BlockingActive = _state.Firewall?.RuleExists("HG_DoT_TCP") ?? false,
            QuicBlocked = _state.Firewall?.RuleExists(FirewallControlServiceImpl.QuicRuleName) ?? false,
            CnameCloak = _state.CnameCloak.Enabled,
            SniCapture = _state.Sni?.Active ?? false,
            DnsEncryptedOnly = Windows.DnsConfig.IsEncryptedDnsOnly(),
            DnrEnabled = Windows.DnsConfig.IsDnrEnabled(),
            HttpsRecords = counts.HttpsRecords,
            SvcbRecords = counts.SvcbRecords,
            EchUnavailableObservations = _state.EchUnavailableSniObservations,
            EchState = posture.State,
            EchSummary = posture.Summary,
            EchRemediation = posture.Remediation,
            ServiceBindingObserved = posture.ServiceBindingObserved,
            EchUnobservable = posture.EchUnobservable,
        });
    }

    public override Task<Ack> SetSniCapture(SniCaptureRequest request, ServerCallContext context)
    {
        if (_state.Sni is not { } sni)
        {
            return Task.FromResult(Error("sni_unavailable", "SNI capture is not available in this service instance"));
        }

        _state.Db.SetMeta("sni_capture", request.Enabled ? "on" : "off");
        if (request.Enabled)
        {
            var status = sni.Start();
            return Task.FromResult(status switch
            {
                Windows.DnsMonitorStatus.Started => Ok("TLS SNI capture on — HTTPS connections resolved over DoH now show their hostname (ECH-encrypted SNI stays unavailable)"),
                Windows.DnsMonitorStatus.RequiresElevation => Error("sni_elevation", "SNI capture requires the elevated service"),
                _ => Error("sni_unavailable", "SNI capture couldn't open a capture socket (it may be blocked by security software)"),
            });
        }

        sni.Stop();
        return Task.FromResult(Ok("TLS SNI capture off"));
    }

    public override async Task<Ack> RefreshDohIntelligence(DohRefreshRequest request, ServerCallContext context)
    {
        var url = (request.Url ?? string.Empty).Trim();
        if (url.Length != 0 &&
            (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps))
        {
            return Error("invalid_source", "DoH resolver list URL must be https://");
        }

        if (url.Length != 0 && _state.ListFetcher is null)
        {
            return Error("lists_unavailable", "no fetcher attached to this service instance");
        }

        try
        {
            var state = await _state.Doh.RefreshAsync(url, request.Sha256, _state.ListFetcher ?? NullFetcher.Instance, context.CancellationToken);
            return Ok($"DoH intelligence refreshed: {state.Ips.Count} learned IPs ({state.Source})");
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or InvalidOperationException or TaskCanceledException or IOException)
        {
            // The prior doh_resolvers.json is untouched on any failure.
            return Error("refresh_failed", ex.Message);
        }
    }

    public override Task<Ack> SetCnameCloak(CnameCloakRequest request, ServerCallContext context)
    {
        _state.CnameCloak.SetEnabled(request.Enabled);
        return Task.FromResult(Ok(request.Enabled
            ? "CNAME-cloak blocking armed — first-party hosts aliasing to blocked trackers are now blocked"
            : "CNAME-cloak blocking disarmed"));
    }

    private static readonly TimeSpan PtrTimeout = TimeSpan.FromSeconds(3);
    private const int MaxResolveBatch = 256;

    public override async Task<ResolveHostsResult> ResolveHosts(ResolveHostsRequest request, ServerCallContext context)
    {
        var result = new ResolveHostsResult();
        var addresses = request.Addresses
            .Select(a => (a ?? string.Empty).Trim())
            .Where(a => IPAddress.TryParse(a, out _))
            .Distinct(StringComparer.Ordinal)
            .Take(MaxResolveBatch)
            .ToList();

        // Answer from the persistent store first (never re-resolve a known IP),
        // then reverse-DNS the rest with bounded concurrency.
        var unresolved = new List<string>();
        foreach (var ip in addresses)
        {
            var known = _state.ResolveKnownHost(ip);
            if (known.Length != 0)
            {
                result.Hosts.Add(new ResolvedHostEntry { Address = ip, Host = known });
            }
            else
            {
                unresolved.Add(ip);
            }
        }

        using var throttle = new SemaphoreSlim(8);
        var resolved = await Task.WhenAll(unresolved.Select(async ip =>
        {
            await throttle.WaitAsync(context.CancellationToken);
            try
            {
                return (Ip: ip, Host: await ReverseLookupAsync(ip, context.CancellationToken));
            }
            finally
            {
                throttle.Release();
            }
        }));

        var learned = resolved.Where(r => r.Host.Length != 0).ToList();
        if (learned.Count != 0)
        {
            _state.Db.UpsertResolvedHosts(learned.Select(r => (r.Ip, r.Host)), "ptr");
        }

        foreach (var (ip, host) in resolved)
        {
            result.Hosts.Add(new ResolvedHostEntry { Address = ip, Host = host });
        }

        return result;
    }

    private static string NormalizeCacheEntryName(string? name)
        => (name ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    private static bool IsValidCacheEntryName(string name)
        => name.Length is > 0 and <= 255 &&
           !name.Any(c => char.IsControl(c) || char.IsWhiteSpace(c) || c is '\\' or '/');

    private static bool IsDnsCacheApiException(Exception ex)
        => ex is EntryPointNotFoundException or DllNotFoundException or InvalidOperationException
            or UnauthorizedAccessException;

    private IReadOnlyList<Windows.DnsCacheRecord> ServiceBindingCacheRows(int limit, string? search)
    {
        if (_state.Dns is not { } dns)
        {
            return Array.Empty<Windows.DnsCacheRecord>();
        }

        try
        {
            var rows = dns.GetCacheEntries(limit, search)
                .Where(row => IsServiceBindingType(row.Type));
            if (!string.IsNullOrWhiteSpace(search))
            {
                var domain = search.Trim().TrimEnd('.').ToLowerInvariant();
                rows = rows.Where(row => IsServiceBindingMatch(row.Name, domain));
            }

            return rows.ToList();
        }
        catch (Exception ex) when (IsDnsCacheApiException(ex))
        {
            return Array.Empty<Windows.DnsCacheRecord>();
        }
    }

    private static bool IsServiceBindingType(string type)
        => string.Equals(type, "HTTPS", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(type, "SVCB", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(type, "64", StringComparison.Ordinal) ||
           string.Equals(type, "65", StringComparison.Ordinal);

    private static bool IsServiceBindingMatch(string name, string domain)
    {
        var n = (name ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        return n.Equals(domain, StringComparison.Ordinal) ||
               n.EndsWith("." + domain, StringComparison.Ordinal);
    }

    private static string DnsCachePrivacyRole(Windows.DnsCacheRecord row)
    {
        var type = row.Type.Equals("HTTPS", StringComparison.OrdinalIgnoreCase) || row.Type == "65"
            ? "HTTPS"
            : "SVCB";
        return row.DataLength > 0
            ? $"{type} service binding cached by Windows ({row.DataLength} bytes; SVCB params not exposed)"
            : $"{type} service binding cached by Windows (SVCB params not exposed)";
    }

    private readonly record struct ServiceBindingCounts(int HttpsRecords, int SvcbRecords);

    private static ServiceBindingCounts CountServiceBindings(IEnumerable<Windows.DnsCacheRecord> rows)
    {
        var https = 0;
        var svcb = 0;
        foreach (var row in rows)
        {
            if (row.Type.Equals("HTTPS", StringComparison.OrdinalIgnoreCase) || row.Type == "65")
            {
                https++;
            }
            else if (row.Type.Equals("SVCB", StringComparison.OrdinalIgnoreCase) || row.Type == "64")
            {
                svcb++;
            }
        }

        return new ServiceBindingCounts(https, svcb);
    }

    private DnsPrivacyPostureResult BuildPosture(ServiceBindingCounts counts)
    {
        var dohBlockingActive = _state.Firewall?.RuleExists("HG_DoT_TCP") ?? false;
        var quicBlocked = _state.Firewall?.RuleExists(FirewallControlServiceImpl.QuicRuleName) ?? false;
        return DnsPrivacyPosture.Evaluate(new DnsPrivacySignals(
            counts.HttpsRecords,
            counts.SvcbRecords,
            _state.Sni?.Active ?? false,
            _state.EchUnavailableSniObservations,
            Windows.DnsConfig.IsEncryptedDnsOnly(),
            dohBlockingActive,
            quicBlocked));
    }

    private static void ApplyPosture(DnsInspectResult result, DnsPrivacyPostureResult posture)
    {
        result.EchState = posture.State;
        result.EchSummary = posture.Summary;
        result.EchRemediation = posture.Remediation;
        result.ServiceBindingObserved = posture.ServiceBindingObserved;
    }

    /// <summary>Reverse-DNS an IP with a hard timeout; "" when it has no PTR name.</summary>
    private static async Task<string> ReverseLookupAsync(string ip, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(PtrTimeout);
            var entry = await Dns.GetHostEntryAsync(ip, cts.Token);
            return entry.HostName.Equals(ip, StringComparison.Ordinal)
                ? string.Empty
                : entry.HostName.ToLowerInvariant();
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException
            or ArgumentException or InvalidOperationException)
        {
            return string.Empty;
        }
    }

    private sealed class NullFetcher : IListFetcher
    {
        public static readonly NullFetcher Instance = new();

        public Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct)
            => throw new InvalidOperationException("no fetcher attached");

        public Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct)
            => throw new InvalidOperationException("no fetcher attached");
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}
