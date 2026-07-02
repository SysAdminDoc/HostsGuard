using System.Runtime.Versioning;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>Implements the HostsControl gRPC service on top of the hosts engine + DB.</summary>
[SupportedOSPlatform("windows")]
public sealed class HostsControlServiceImpl : HostsControl.HostsControlBase
{
    private readonly ServiceState _state;

    public HostsControlServiceImpl(ServiceState state) => _state = state;

    public override Task<Ack> Block(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        var wrote = _state.Hosts.Block(d);
        _state.Db.AddDomain(d, "blocked", string.IsNullOrEmpty(request.Source) ? "manual" : request.Source, reason: request.Reason);
        _state.Db.LogEvent(d, "blocked", details: "hosts file", reason: request.Reason);
        return Task.FromResult(Ok(wrote ? $"blocked {d}" : $"already blocked {d}"));
    }

    public override Task<Ack> Allow(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        _state.Hosts.Unblock(d);
        _state.Db.AddDomain(d, "whitelisted", string.IsNullOrEmpty(request.Source) ? "manual" : request.Source, reason: request.Reason);
        _state.Db.LogEvent(d, "whitelisted", reason: request.Reason);
        return Task.FromResult(Ok($"allowed {d}"));
    }

    public override Task<Ack> Unblock(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        _state.Hosts.Unblock(d);
        _state.Db.RemoveDomain(d);
        return Task.FromResult(Ok($"unblocked {d}"));
    }

    public override Task<Ack> BlockRoot(DomainRequest request, ServerCallContext context)
    {
        var d = (request.Domain ?? string.Empty).ToLowerInvariant().Trim();
        if (!Domains.LooksLikeDomain(d))
        {
            return Task.FromResult(Error("invalid_domain", $"'{request.Domain}' is not a valid domain"));
        }

        var root = Domains.GetRoot(d);
        _state.Hosts.Block(root);
        _state.Db.AddDomain(root, "blocked", "manual", reason: request.Reason);
        return Task.FromResult(Ok($"blocked root {root}"));
    }

    public override Task<DomainList> ListDomains(ListDomainsRequest request, ServerCallContext context)
    {
        var rows = _state.Db.GetDomains(
            string.IsNullOrEmpty(request.Status) ? null : request.Status,
            string.IsNullOrEmpty(request.Search) ? null : request.Search,
            string.IsNullOrEmpty(request.Source) ? null : request.Source);

        var list = new DomainList();
        foreach (var r in rows)
        {
            list.Domains.Add(new ManagedDomain
            {
                Domain = r.Domain,
                Status = r.Status,
                Source = r.Source ?? string.Empty,
                Reason = r.Reason ?? string.Empty,
                Hits = r.Hits,
                Notes = r.Notes ?? string.Empty,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> Reconcile(ReconcileRequest request, ServerCallContext context)
    {
        var (added, target) = _state.Hosts.Reconcile(request.Blocked);
        return Task.FromResult(Ok($"reconciled: +{added} to {target} target"));
    }

    public override Task<Ack> EmergencyReset(Empty request, ServerCallContext context)
    {
        _state.Hosts.EmergencyReset();
        return Task.FromResult(Ok("hosts file reset to Windows defaults"));
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}
