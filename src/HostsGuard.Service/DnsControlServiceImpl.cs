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

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}
