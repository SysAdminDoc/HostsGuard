using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Opt-in immediate IPv4 TCP teardown after blocks land (NET-152). The service
/// never terminates UDP or IPv6 flows; manual close is available regardless of
/// the auto-teardown toggle.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FlowTeardownCoordinator
{
    private const string MetaKey = "flow_teardown_enabled";

    private readonly HostsDatabase _db;
    private readonly IFlowTerminator? _terminator;
    private readonly Func<IReadOnlyList<ConnectionInfo>> _snapshot;

    public FlowTeardownCoordinator(
        HostsDatabase db,
        IFlowTerminator? terminator,
        Func<IReadOnlyList<ConnectionInfo>> snapshot)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _terminator = terminator;
        _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
    }

    public bool Available => _terminator is not null;

    public bool Enabled
    {
        get => _db.GetMeta(MetaKey) == "1";
        set => _db.SetMeta(MetaKey, value ? "1" : "0");
    }

    public Ack SetEnabled(bool enabled)
    {
        if (enabled && !Available)
        {
            return Error("flow_teardown_unavailable", "flow teardown is unavailable in this service instance");
        }

        Enabled = enabled;
        _db.LogEvent("flow-teardown", enabled ? "fw_flow_teardown_on" : "fw_flow_teardown_off", reason: "manual");
        return new Ack
        {
            Ok = true,
            Message = enabled
                ? "TCP flow teardown enabled for future blocks (IPv4 only)"
                : "TCP flow teardown disabled",
        };
    }

    public Ack CloseManual(FlowTuple flow) => CloseOne(flow, "manual");

    public int CloseForRemoteAddress(string remoteAddress, string reason)
    {
        if (!Enabled || !IPAddress.TryParse(remoteAddress, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return 0;
        }

        return CloseMatching(
            c => string.Equals(c.RemoteAddress, remoteAddress, StringComparison.Ordinal),
            reason);
    }

    public int CloseForProgram(string programPath, string reason, string? remoteAddress = null, int remotePort = 0)
    {
        if (!Enabled)
        {
            return 0;
        }

        var stem = Path.GetFileNameWithoutExtension(programPath);
        if (string.IsNullOrWhiteSpace(stem))
        {
            return 0;
        }

        return CloseMatching(c =>
            string.Equals(c.Process, stem, StringComparison.OrdinalIgnoreCase)
            && (string.IsNullOrWhiteSpace(remoteAddress) || string.Equals(c.RemoteAddress, remoteAddress, StringComparison.Ordinal))
            && (remotePort <= 0 || c.RemotePort == remotePort), reason);
    }

    public int CloseInternetForKillSwitch()
    {
        if (!Enabled)
        {
            return 0;
        }

        return CloseMatching(c =>
        {
            if (!IPAddress.TryParse(c.RemoteAddress, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            return NetworkScopes.IsInternet(ip);
        }, "killswitch");
    }

    private int CloseMatching(Func<ConnectionInfo, bool> predicate, string reason)
    {
        if (_terminator is null)
        {
            return 0;
        }

        var closed = 0;
        foreach (var c in _snapshot().Where(c =>
                     string.Equals(c.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                     && string.Equals(c.State, "ESTABLISHED", StringComparison.OrdinalIgnoreCase)
                     && predicate(c)))
        {
            var ack = CloseOne(new FlowTuple(c.Protocol, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort, c.Process), reason);
            if (ack.Ok)
            {
                closed++;
            }
        }

        return closed;
    }

    private Ack CloseOne(FlowTuple flow, string reason)
    {
        if (_terminator is null)
        {
            return Error("flow_teardown_unavailable", "flow teardown is unavailable in this service instance");
        }

        var result = _terminator.CloseTcp4(flow);
        if (result.Ok)
        {
            _db.LogEvent(
                $"{flow.RemoteAddress}:{flow.RemotePort}",
                EventTaxonomy.FwFlowTeardown,
                process: flow.Process,
                details: $"{flow.LocalAddress}:{flow.LocalPort} -> {flow.RemoteAddress}:{flow.RemotePort} ({reason}; IPv4 TCP)",
                reason: reason);
            return new Ack { Ok = true, Message = result.Message };
        }

        return new Ack { Ok = false, Message = result.Message, ErrorCode = result.ErrorCode };
    }

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}
