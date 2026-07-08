using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

[SupportedOSPlatform("windows")]
public sealed class AppVpnBindingCoordinator : IDisposable
{
    private const string RulePrefix = "HG_VPNBind_";
    private static readonly TimeSpan NetworkDebounce = TimeSpan.FromSeconds(3);

    private readonly IFirewallEngine? _firewall;
    private readonly HostsDatabase _db;
    private readonly Func<IReadOnlyList<AdapterInfo>> _listAdapters;
    private readonly object _gate = new();
    private Timer? _timer;
    private bool _started;
    private bool _disposed;

    public AppVpnBindingCoordinator(
        IFirewallEngine? firewall,
        HostsDatabase db,
        Func<IReadOnlyList<AdapterInfo>> listAdapters)
    {
        _firewall = firewall;
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _listAdapters = listAdapters ?? throw new ArgumentNullException(nameof(listAdapters));
    }

    public IReadOnlyList<AppVpnBindingView> List()
    {
        var adapters = SafeAdapters();
        return _db.ListAppVpnBindings()
            .Select(row => ToView(row, adapters))
            .ToList();
    }

    public IReadOnlyList<AdapterInfo> ListAdapters() => SafeAdapters();

    public Ack Set(string program, string adapter, bool enabled)
    {
        program = (program ?? string.Empty).Trim();
        adapter = (adapter ?? string.Empty).Trim();
        if (program.Length == 0)
        {
            return Error("invalid_program", "program path is required");
        }

        var ruleName = RuleNameFor(program);
        if (!enabled)
        {
            _db.RemoveAppVpnBinding(program);
            _firewall?.DeleteRule(ruleName);
            _db.RemoveFwState(ruleName);
            _db.LogEvent(program, "app_vpn_unbound", details: ruleName, reason: "manual");
            return Ok($"removed VPN binding for {program}");
        }

        if (_firewall is null)
        {
            return Error("firewall_unavailable", "firewall engine is not attached");
        }

        if (adapter.Length == 0)
        {
            return Error("invalid_adapter", "adapter is required");
        }

        _db.UpsertAppVpnBinding(program, adapter, ruleName);
        var reconciled = ReconcileOne(_db.ListAppVpnBindings()
            .First(row => string.Equals(row.Program, program, StringComparison.Ordinal)));
        _db.LogEvent(program, "app_vpn_bound", details: $"adapter={adapter}; rule={ruleName}", reason: "manual");
        return Ok(reconciled
            ? $"bound {program} to '{adapter}'"
            : $"saved VPN binding for {program}; no non-selected active interfaces need blocking right now");
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }

            _timer = new Timer(_ => ReconcileSafely(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            NetworkChange.NetworkAddressChanged += OnNetworkChanged;
            _started = true;
        }

        ReconcileSafely();
    }

    public void ReconcileAll()
    {
        if (_firewall is null)
        {
            return;
        }

        var rows = _db.ListAppVpnBindings();
        var expected = rows.Select(r => r.RuleName).ToHashSet(StringComparer.Ordinal);
        foreach (var rule in _firewall.ListRules()
            .Where(r => r.Name.StartsWith(RulePrefix, StringComparison.Ordinal) && !expected.Contains(r.Name)))
        {
            _firewall.DeleteRule(rule.Name);
            _db.RemoveFwState(rule.Name);
        }

        foreach (var row in rows)
        {
            ReconcileOne(row);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            if (_started)
            {
                NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
            }

            _timer?.Dispose();
            _disposed = true;
        }
    }

    private bool ReconcileOne(AppVpnBindingRow row)
    {
        if (_firewall is null)
        {
            return false;
        }

        var view = ToView(row, SafeAdapters());
        if (view.BlockedInterfaces.Count == 0)
        {
            _firewall.DeleteRule(row.RuleName);
            _db.RemoveFwState(row.RuleName);
            return false;
        }

        var interfaces = string.Join(',', view.BlockedInterfaces);
        var desired = new FwRule(
            row.RuleName,
            "Out",
            "Block",
            true,
            "Any",
            "Any",
            row.Program,
            "hostsguard",
            Interfaces: interfaces);

        var existing = _firewall.ListRules().FirstOrDefault(r => string.Equals(r.Name, row.RuleName, StringComparison.Ordinal));
        if (existing is null || !SameBindingRule(existing, desired))
        {
            if (existing is not null)
            {
                _firewall.DeleteRule(existing.Name);
            }

            if (!_firewall.CreateRule(desired))
            {
                return false;
            }
        }

        _db.UpsertFwState(
            desired.Name,
            desired.Direction,
            desired.Action,
            desired.RemoteAddr,
            desired.Protocol,
            desired.Program,
            desired.RemotePorts,
            desired.LocalPorts,
            desired.ServiceName,
            desired.Interfaces);
        return true;
    }

    private AppVpnBindingView ToView(AppVpnBindingRow row, IReadOnlyList<AdapterInfo> adapters)
    {
        var selectedUp = adapters.Any(a => a.IsUp && NetworkAdapters.Matches(a.Name, a.Description, row.Adapter));
        var blocked = adapters
            .Where(a => a.IsUp && !NetworkAdapters.Matches(a.Name, a.Description, row.Adapter))
            .Select(a => a.Name)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return new AppVpnBindingView(row.Program, row.Adapter, row.RuleName, selectedUp, blocked);
    }

    private IReadOnlyList<AdapterInfo> SafeAdapters()
    {
        try
        {
            return _listAdapters();
        }
        catch
        {
            return Array.Empty<AdapterInfo>();
        }
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        lock (_gate)
        {
            if (_disposed || _timer is null)
            {
                return;
            }

            _timer.Change(NetworkDebounce, Timeout.InfiniteTimeSpan);
        }
    }

    private void ReconcileSafely()
    {
        try
        {
            ReconcileAll();
        }
        catch (Exception ex)
        {
            _db.LogEvent("app_vpn", "app_vpn_reconcile_failed", details: ex.Message, reason: "firewall");
        }
    }

    private static bool SameBindingRule(FwRule current, FwRule desired)
        => current.Enabled == desired.Enabled
            && string.Equals(current.Direction, desired.Direction, StringComparison.Ordinal)
            && string.Equals(current.Action, desired.Action, StringComparison.Ordinal)
            && string.Equals(current.RemoteAddr, desired.RemoteAddr, StringComparison.OrdinalIgnoreCase)
            && string.Equals(current.Protocol, desired.Protocol, StringComparison.OrdinalIgnoreCase)
            && string.Equals(current.Program, desired.Program, StringComparison.OrdinalIgnoreCase)
            && SameInterfaces(current.Interfaces, desired.Interfaces);

    private static bool SameInterfaces(string left, string right)
    {
        var a = SplitInterfaces(left);
        var b = SplitInterfaces(right);
        return a.SetEquals(b);
    }

    private static HashSet<string> SplitInterfaces(string value)
        => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(v => !v.Equals("Any", StringComparison.OrdinalIgnoreCase))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static string RuleNameFor(string program)
    {
        var normalized = (program ?? string.Empty).Trim().ToLowerInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));
        return RulePrefix + hash[..16];
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) => new()
    {
        Ok = false,
        ErrorCode = "hostsguard.error.v1/" + code,
        Message = message,
    };
}

public sealed record AppVpnBindingView(
    string Program,
    string Adapter,
    string RuleName,
    bool SelectedAdapterUp,
    IReadOnlyList<string> BlockedInterfaces);
