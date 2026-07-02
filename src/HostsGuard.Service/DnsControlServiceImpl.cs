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
    private readonly ServiceState _state;

    public DnsControlServiceImpl(ServiceState state) => _state = state;

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

    public override Task<Ack> SetResolver(ResolverRequest request, ServerCallContext context)
    {
        if (_state.Dns is not { } dns)
        {
            return Task.FromResult(Error("dns_unavailable", "DNS engine is not attached to this service instance"));
        }

        var servers = request.Servers.Select(s => s.Trim()).Where(s => s.Length != 0).ToList();
        if (servers.Any(s => !IPAddress.TryParse(s, out _)))
        {
            return Task.FromResult(Error("invalid_resolver", "resolver list contains a non-IP entry"));
        }

        var changed = dns.SetResolvers(servers);
        _state.Db.LogEvent("dns", "resolver_switch",
            details: servers.Count == 0 ? "reset to DHCP" : string.Join(",", servers));
        return Task.FromResult(Ok(servers.Count == 0
            ? $"reset {changed.Count} adapters to DHCP DNS"
            : $"set {string.Join(",", servers)} on {changed.Count} adapters"));
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

        return result;
    }

    public override Task<DohStatus> GetDohStatus(Empty request, ServerCallContext context)
    {
        var state = _state.Doh.Load();
        var extras = Core.DohResolvers.NormalizeIpSet(state.Ips);
        extras.ExceptWith(Core.DohResolvers.NormalizeIpSet(Core.DohResolvers.BuiltIn));
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
        });
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
