using Dapper;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
    public IReadOnlyList<AppVpnBindingRow> ListAppVpnBindings()
    {
        lock (_gate)
        {
            return _conn.Query<AppVpnBindingRow>(
                """
                SELECT program AS Program, adapter AS Adapter, rule_name AS RuleName,
                       created AS Created, updated AS Updated
                FROM app_vpn_bindings
                ORDER BY program
                """).ToList();
        }
    }

    public void UpsertAppVpnBinding(string program, string adapter, string ruleName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(program);
        ArgumentException.ThrowIfNullOrWhiteSpace(adapter);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO app_vpn_bindings(program,adapter,rule_name,created,updated)
                VALUES(@program,@adapter,@ruleName,@now,@now)
                ON CONFLICT(program) DO UPDATE SET
                    adapter=excluded.adapter,
                    rule_name=excluded.rule_name,
                    updated=excluded.updated
                """,
                new { program = program.Trim(), adapter = adapter.Trim(), ruleName = ruleName.Trim(), now });
        }
    }

    public bool RemoveAppVpnBinding(string program)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(program);
        lock (_gate)
        {
            return _conn.Execute("DELETE FROM app_vpn_bindings WHERE program=@program", new { program = program.Trim() }) != 0;
        }
    }

    public bool RemoveAppVpnBindingByRuleName(string ruleName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
        lock (_gate)
        {
            return _conn.Execute("DELETE FROM app_vpn_bindings WHERE rule_name=@ruleName", new { ruleName = ruleName.Trim() }) != 0;
        }
    }
}
