using System.Globalization;
using System.Text;
using Dapper;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
    public void UpsertDomainFirewallRule(
        string domain,
        string program,
        string ruleName,
        string action,
        bool enabled,
        string remoteAddr)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO domain_firewall_rules(domain, program, rule_name, action, enabled, remote_addr, updated, created)
                VALUES(@domain, @program, @ruleName, @action, @enabled, @remoteAddr, @now, @now)
                ON CONFLICT(domain, program) DO UPDATE SET
                    rule_name=excluded.rule_name,
                    action=excluded.action,
                    enabled=excluded.enabled,
                    remote_addr=excluded.remote_addr,
                    updated=excluded.updated
                """,
                new
                {
                    domain = domain.ToLowerInvariant(),
                    program = program ?? string.Empty,
                    ruleName,
                    action = string.IsNullOrWhiteSpace(action) ? "Block" : action.Trim(),
                    enabled = enabled ? 1 : 0,
                    remoteAddr = remoteAddr ?? string.Empty,
                    now,
                });
        }
    }

    public void UpdateDomainFirewallRuleRemote(string ruleName, string remoteAddr)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                UPDATE domain_firewall_rules
                SET remote_addr=@remoteAddr, updated=@now
                WHERE rule_name=@ruleName
                """,
                new { ruleName, remoteAddr = remoteAddr ?? string.Empty, now });
        }
    }

    public IReadOnlyList<DomainFirewallRuleRow> ListDomainFirewallRules()
    {
        lock (_gate)
        {
            return QueryDomainFirewallRules(
                """
                SELECT domain AS Domain, program AS Program, rule_name AS RuleName,
                       action AS Action, enabled AS Enabled, remote_addr AS RemoteAddr,
                       updated AS Updated, created AS Created
                FROM domain_firewall_rules
                ORDER BY updated DESC, domain
                """);
        }
    }

    public IReadOnlyList<DomainFirewallRuleRow> GetDomainFirewallRulesForDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return Array.Empty<DomainFirewallRuleRow>();
        }

        lock (_gate)
        {
            return QueryDomainFirewallRules(
                """
                SELECT domain AS Domain, program AS Program, rule_name AS RuleName,
                       action AS Action, enabled AS Enabled, remote_addr AS RemoteAddr,
                       updated AS Updated, created AS Created
                FROM domain_firewall_rules
                WHERE domain=@domain
                ORDER BY program
                """,
                new { domain = domain.ToLowerInvariant().Trim() });
        }
    }

    public bool RemoveDomainFirewallRule(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            return false;
        }

        lock (_gate)
        {
            return _conn.Execute(
                "DELETE FROM domain_firewall_rules WHERE rule_name=@ruleName",
                new { ruleName = ruleName.Trim() }) > 0;
        }
    }

    public IReadOnlyList<string> GetResolvedAddressesForHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return Array.Empty<string>();
        }

        lock (_gate)
        {
            return _conn.Query<string>(
                "SELECT ip FROM resolved_hosts WHERE host=@host ORDER BY updated DESC, ip",
                new { host = host.ToLowerInvariant().Trim() }).ToList();
        }
    }

    private IReadOnlyList<DomainFirewallRuleRow> QueryDomainFirewallRules(string sql, object? param = null)
    {
        return _conn.Query(sql, param)
            .Select(row =>
            {
                var values = (IDictionary<string, object?>)row;
                return new DomainFirewallRuleRow(
                    Text(values["Domain"]),
                    Text(values["Program"]),
                    Text(values["RuleName"]),
                    NonEmpty(Text(values["Action"]), "Block"),
                    Enabled(values["Enabled"]),
                    Text(values["RemoteAddr"]),
                    Text(values["Updated"]),
                    Text(values["Created"]));
            })
            .ToList();
    }

    private static string NonEmpty(string value, string fallback) => value.Length == 0 ? fallback : value;

    private static string Text(object? value) => value switch
    {
        null or DBNull => string.Empty,
        byte[] bytes => Encoding.UTF8.GetString(bytes),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty,
    };

    private static bool Enabled(object? value) => value switch
    {
        null or DBNull => false,
        bool b => b,
        byte[] bytes => Enabled(Encoding.UTF8.GetString(bytes)),
        int i => i != 0,
        long l => l != 0,
        string s => s is "1" or "true" or "True",
        _ => Convert.ToInt64(value, CultureInfo.InvariantCulture) != 0,
    };
}
