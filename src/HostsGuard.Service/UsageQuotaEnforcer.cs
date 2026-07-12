using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Optional usage-budget enforcement (NET-172): a quota rule that opts into
/// "block on exceed" gets a scoped block when its rolling window crosses the
/// limit — a hosts-file block for domain rules, HG_QuotaBlock_* outbound
/// firewall rules for app rules (resolved from the running processes that
/// match the rule's process name). The block clears automatically when the
/// window slides back under the limit, and is reversible in one click via
/// disable/delete/reset. Defaults OFF per rule; manual allowlists always win.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class UsageQuotaEnforcer
{
    /// <summary>Domain-row source; the enforcer only ever reverts rows it owns.</summary>
    public const string DomainSource = "quota";

    private readonly HostsDatabase _db;
    private readonly HostsEngine _hosts;
    private readonly IFirewallEngine? _firewall;
    private readonly Func<string, IReadOnlyList<string>> _processPaths;
    private readonly object _gate = new();

    public UsageQuotaEnforcer(
        HostsDatabase db,
        HostsEngine hosts,
        IFirewallEngine? firewall,
        Func<string, IReadOnlyList<string>>? processPathResolver = null)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _hosts = hosts ?? throw new ArgumentNullException(nameof(hosts));
        _firewall = firewall;
        _processPaths = processPathResolver ?? DefaultProcessPaths;
    }

    /// <summary>Evaluate every block-on-exceed rule: apply overdue blocks, clear stale ones.</summary>
    public void Sweep(DateTime now)
    {
        lock (_gate)
        {
            foreach (var rule in _db.GetUsageQuotaRules())
            {
                var blockActive = rule.BlockedSince.Length != 0;
                if (!rule.Enabled || !rule.BlockOnExceed)
                {
                    if (blockActive)
                    {
                        ClearBlock(rule, "rule disabled or block-on-exceed turned off");
                    }

                    continue;
                }

                var used = _db.GetUsageBytesForQuota(rule.Scope, rule.Match, rule.WindowDays, now);
                if (used >= rule.LimitBytes)
                {
                    // Re-derive from real state rather than trusting blockedSince:
                    // the block can go missing while blockedSince is still set —
                    // e.g. the enforcer recorded blockedSince over a pre-existing
                    // block it didn't own, and the user later deleted that block.
                    // Without this the quota silently stops enforcing until the
                    // window slides. Only (re-)apply when the block isn't in place.
                    if (!IsBlockInPlace(rule))
                    {
                        ApplyBlock(rule, used, now);
                    }
                }
                else if (blockActive)
                {
                    ClearBlock(rule, "usage window fell back under the limit");
                }
            }
        }
    }

    /// <summary>Clear an active block for one rule (delete/disable/reset paths).</summary>
    public void ClearBlockById(long id, string reason)
    {
        lock (_gate)
        {
            var rule = _db.GetUsageQuotaRules().FirstOrDefault(r => r.Id == id);
            if (rule is not null && rule.BlockedSince.Length != 0)
            {
                ClearBlock(rule, reason);
            }
        }
    }

    /// <summary>Clear every active quota block (reset path). Returns how many cleared.</summary>
    public int ClearAllBlocks(string reason)
    {
        lock (_gate)
        {
            var cleared = 0;
            foreach (var rule in _db.GetUsageQuotaRules().Where(r => r.BlockedSince.Length != 0))
            {
                ClearBlock(rule, reason);
                cleared++;
            }

            return cleared;
        }
    }

    /// <summary>
    /// True when the rule's block is actually in force right now — so an over-limit
    /// sweep only (re-)applies when the block has genuinely gone missing, not just
    /// because <c>blockedSince</c> is set.
    /// </summary>
    private bool IsBlockInPlace(UsageQuotaRuleRow rule)
    {
        if (rule.Scope == "domain")
        {
            // Blocked (by us or anyone) or manually whitelisted → nothing to apply.
            var status = _db.GetDomainStatus(rule.Match);
            return status is "blocked" or "whitelisted";
        }

        // App scope: in place only if we recorded rule names and every one still
        // exists in the firewall (a manual rule delete drops us back to not-in-place).
        if (rule.BlockedRules.Length == 0 || _firewall is not { } fw)
        {
            return false;
        }

        var names = rule.BlockedRules.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return names.Length != 0 && names.All(fw.RuleExists);
    }

    private void ApplyBlock(UsageQuotaRuleRow rule, long used, DateTime now)
    {
        string detail;
        var blockedRules = string.Empty;
        if (rule.Scope == "domain")
        {
            // A manual whitelist always wins over automated enforcement.
            if (_db.GetDomainStatus(rule.Match) == "whitelisted" && _db.GetDomainSource(rule.Match) != DomainSource)
            {
                _db.LogEvent(rule.Match, "usage_budget_block_skipped",
                    details: "quota exceeded but the domain is manually whitelisted", reason: "usage_budget");
                return;
            }

            if (_db.GetDomainStatus(rule.Match) == "blocked")
            {
                // Already blocked (e.g. manually) — track the exceed but leave
                // the row's ownership alone so clearing never lifts that block.
                detail = $"{rule.Match} is already blocked";
            }
            else
            {
                _hosts.Block(rule.Match);
                _db.AddDomain(rule.Match, "blocked", DomainSource);
                detail = $"hosts-blocked {rule.Match}";
            }
        }
        else
        {
            if (_firewall is not { } fw)
            {
                return; // no engine attached — retry on a later sweep
            }

            var paths = _processPaths(rule.Match);
            if (paths.Count == 0)
            {
                // Not running right now — retried every sweep until a path resolves.
                _db.LogEvent(rule.Match, "usage_budget_block_pending", process: rule.Match,
                    details: "quota exceeded; waiting for a running process to resolve the executable path",
                    reason: "usage_budget");
                return;
            }

            var names = new List<string>();
            foreach (var path in paths)
            {
                var name = RuleName(rule.Match, path);
                var created = fw.RuleExists(name) || fw.CreateRule(
                    new FwRule(name, "Out", "Block", Enabled: true, "Any", "Any", path, "hostsguard"));
                if (created)
                {
                    _db.UpsertFwState(name, "Out", "Block", "Any", "Any", path);
                    names.Add(name);
                }
            }

            if (names.Count == 0)
            {
                return;
            }

            blockedRules = string.Join('\n', names);
            detail = $"created {names.Count} HG_QuotaBlock_* firewall rule{(names.Count == 1 ? string.Empty : "s")}";
        }

        _db.SetUsageQuotaBlockState(rule.Id, now.ToString("o", System.Globalization.CultureInfo.InvariantCulture), blockedRules);
        _db.AddAlert(
            "usage_budget",
            "warning",
            "Usage budget exceeded — blocked",
            $"{rule.Scope}:{rule.Match}",
            $"{rule.Match} used {used:N0} of {rule.LimitBytes:N0} bytes over {rule.WindowDays} day{(rule.WindowDays == 1 ? string.Empty : "s")}; {detail}. The block clears when usage falls back under the limit, or disable the rule to lift it now.",
            action: "usage_quota_block",
            process: rule.Scope == "app" ? rule.Match : string.Empty);
        _db.LogEvent(rule.Match, "usage_budget_block", process: rule.Scope == "app" ? rule.Match : string.Empty,
            details: detail, reason: "usage_budget");
    }

    private void ClearBlock(UsageQuotaRuleRow rule, string reason)
    {
        if (rule.Scope == "domain")
        {
            // Only revert a row this enforcer created — never a manual block.
            if (_db.GetDomainStatus(rule.Match) == "blocked" && _db.GetDomainSource(rule.Match) == DomainSource)
            {
                _hosts.Unblock(rule.Match);
                _db.RemoveDomain(rule.Match);
            }
        }
        else
        {
            foreach (var name in rule.BlockedRules.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                _firewall?.DeleteRule(name);
                _db.RemoveFwState(name);
            }
        }

        _db.SetUsageQuotaBlockState(rule.Id, string.Empty, string.Empty);
        _db.LogEvent(rule.Match, "usage_budget_unblock", process: rule.Scope == "app" ? rule.Match : string.Empty,
            details: reason, reason: "usage_budget");
    }

    internal static string RuleName(string processName, string path)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path.ToLowerInvariant())))[..8];
        var slug = new string(processName.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray());
        if (slug.Length > 32)
        {
            slug = slug[..32];
        }

        return $"HG_QuotaBlock_{slug}_{hash}_Out";
    }

    private static IReadOnlyList<string> DefaultProcessPaths(string processName)
    {
        var name = Path.GetFileNameWithoutExtension((processName ?? string.Empty).Trim());
        if (name.Length == 0)
        {
            return Array.Empty<string>();
        }

        var paths = new List<string>();
        foreach (var process in System.Diagnostics.Process.GetProcessesByName(name))
        {
            try
            {
                var path = process.MainModule?.FileName;
                if (!string.IsNullOrEmpty(path))
                {
                    paths.Add(path);
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException)
            {
                // Access denied / exited between snapshot and inspection — skip.
            }
            finally
            {
                process.Dispose();
            }
        }

        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
