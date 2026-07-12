using System.Net;
using System.Security.Cryptography;
using System.Text;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Maintains HG_Domain_* firewall rules whose remote-address lists follow DNS
/// answers. The persisted row is intent; the live Windows Firewall rule is
/// rebuilt/updated whenever answers are known.
/// </summary>
public sealed class DomainFirewallRuleCoordinator : IDisposable
{
    private const int MaxRemoteAddresses = 128;
    private static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromMinutes(30);

    private readonly HostsDatabase _db;
    private readonly IFirewallEngine? _firewall;
    private readonly Func<string, CancellationToken, Task<IReadOnlyList<string>>> _resolver;
    private readonly object _gate = new();
    private readonly ScheduledTaskDrain _scheduledRefresh = new();
    private Timer? _timer;
    private bool _refreshing;

    public DomainFirewallRuleCoordinator(
        HostsDatabase db,
        IFirewallEngine? firewall,
        Func<string, CancellationToken, Task<IReadOnlyList<string>>>? resolver = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _firewall = firewall;
        _resolver = resolver ?? ResolveAsync;
    }

    public void StartPeriodic(TimeSpan? interval = null)
    {
        if (_timer is not null)
        {
            return;
        }

        var every = interval ?? DefaultRefreshInterval;
        _timer = new Timer(_ => KickScheduledRefresh(), null, every, every);
    }

    public IReadOnlyList<DomainFirewallRuleRow> List() => _db.ListDomainFirewallRules();

    public async Task<Ack> CreateOrUpdateAsync(string domain, string programPath, CancellationToken cancellationToken)
    {
        var d = NormalizeDomain(domain);
        if (!Domains.LooksLikeDomain(d))
        {
            return Error("invalid_domain", "domain is required");
        }

        var program = (programPath ?? string.Empty).Trim();
        if (program.Length == 0 || program.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            return Error("invalid_program", "a per-app program path is required to avoid CDN IP over-blocking");
        }

        var ruleName = RuleName(d, program);
        var known = _db.GetResolvedAddressesForHost(d);
        var resolved = known.Count == 0
            ? await SafeResolveAsync(d, cancellationToken)
            : known;
        var remote = RemoteAddressList(resolved);

        _db.UpsertDomainFirewallRule(d, program, ruleName, "Block", enabled: true, remote);
        if (remote.Length == 0)
        {
            _db.LogEvent(d, "domain_fw_pending", process: Path.GetFileName(program),
                details: $"{ruleName}; waiting for DNS answers", reason: "domain_firewall");
            return Ok($"tracking {d} for {Path.GetFileName(program)} - rule will populate after DNS answers are observed");
        }

        var applied = ApplyLiveRule(new DomainFirewallRuleRow(
            d, program, ruleName, "Block", true, remote, string.Empty, string.Empty), remote);
        return applied
            ? Ok($"domain firewall armed for {d} ({Path.GetFileName(program)} -> {remote})")
            : Error("firewall_unavailable", "firewall engine is not attached");
    }

    public Ack Delete(string ruleName)
    {
        var name = (ruleName ?? string.Empty).Trim();
        if (!name.StartsWith("HG_Domain_", StringComparison.Ordinal))
        {
            return Error("not_ours", "only HG_Domain_ rules can be deleted through this path");
        }

        _firewall?.DeleteRule(name);
        _db.RemoveFwState(name);
        var removed = _db.RemoveDomainFirewallRule(name);
        return removed ? Ok($"deleted {name}") : Error("not_found", $"{name} does not exist");
    }

    public void ObserveResolution(string domain, IReadOnlyList<string> addresses)
    {
        var d = NormalizeDomain(domain);
        if (d.Length == 0 || addresses.Count == 0)
        {
            return;
        }

        var remote = RemoteAddressList(addresses);
        if (remote.Length == 0)
        {
            return;
        }

        foreach (var row in _db.GetDomainFirewallRulesForDomain(d).Where(r => r.Enabled))
        {
            ApplyLiveRule(row, remote);
        }
    }

    public async Task<int> RefreshAllAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_refreshing)
            {
                return 0;
            }

            _refreshing = true;
        }

        try
        {
            var changed = 0;
            foreach (var row in _db.ListDomainFirewallRules().Where(r => r.Enabled))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var addresses = await SafeResolveAsync(row.Domain, cancellationToken);
                var remote = RemoteAddressList(addresses);
                if (remote.Length == 0)
                {
                    continue;
                }

                if (ApplyLiveRule(row, remote))
                {
                    changed++;
                }
            }

            return changed;
        }
        finally
        {
            lock (_gate)
            {
                _refreshing = false;
            }
        }
    }

    internal void KickScheduledRefresh() => _scheduledRefresh.TryRun(SafeRefreshAllAsync);

    private async Task SafeRefreshAllAsync(CancellationToken cancellationToken)
    {
        try
        {
            await RefreshAllAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Owner disposal cancels an in-flight scheduled refresh.
        }
        catch (Exception ex)
        {
            try
            {
                _db.LogEvent("domain_firewall", "refresh_error", details: $"{ex.GetType().Name}: {ex.Message}");
            }
            catch (Exception)
            {
            }
        }
    }

    private bool ApplyLiveRule(DomainFirewallRuleRow row, string remote)
    {
        if (_firewall is not { } fw)
        {
            return false;
        }

        var rule = new FwRule(row.RuleName, "Out", row.Action, row.Enabled, remote, "Any", row.Program, "hostsguard");
        var applied = fw.RuleExists(row.RuleName)
            ? fw.SetRuleRemoteAddresses(row.RuleName, remote) && fw.SetRuleEnabled(row.RuleName, row.Enabled)
            : fw.CreateRule(rule);
        if (!applied)
        {
            return false;
        }

        _db.UpdateDomainFirewallRuleRemote(row.RuleName, remote);
        _db.UpsertFwState(row.RuleName, "Out", row.Action, remote, "Any", row.Program);
        _db.LogEvent(row.Domain, "domain_fw_refreshed", process: Path.GetFileName(row.Program),
            details: $"{row.RuleName}: {remote}", reason: "domain_firewall");
        return true;
    }

    private async Task<IReadOnlyList<string>> SafeResolveAsync(string domain, CancellationToken cancellationToken)
    {
        try
        {
            return await _resolver(domain, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or System.Net.Sockets.SocketException or OperationCanceledException)
        {
            return Array.Empty<string>();
        }
    }

    private static async Task<IReadOnlyList<string>> ResolveAsync(string domain, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(domain, cancellationToken);
        return addresses.Select(a => a.ToString()).ToList();
    }

    private static string RemoteAddressList(IEnumerable<string> addresses) =>
        string.Join(",", addresses
            .Select(a => (a ?? string.Empty).Trim())
            .Where(a => IPAddress.TryParse(a, out _))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(a => a, StringComparer.Ordinal)
            .Take(MaxRemoteAddresses));

    private static string NormalizeDomain(string domain) =>
        (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    internal static string RuleName(string domain, string programPath)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{domain}|{programPath}")))[..12];
        var slug = new string(domain.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray());
        if (slug.Length > 48)
        {
            slug = slug[..48];
        }

        return $"HG_Domain_{slug}_{hash}";
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };

    public void Dispose()
    {
        _timer?.Dispose();
        _timer = null;
        _scheduledRefresh.Dispose();
    }
}
