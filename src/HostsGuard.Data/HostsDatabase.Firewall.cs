using Dapper;
using HostsGuard.Core;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
    // ─── Firewall state (drift tracking) ──────────────────────────────────────

    /// <summary>Track a HostsGuard-created rule so drift (deleted-behind-our-back) is detectable.</summary>
    public void UpsertFwState(string name, string direction, string action, string remoteAddr, string protocol, string program)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT OR REPLACE INTO fw_state(name,direction,action,remote_addr,protocol,program,created)
                VALUES(@name,@direction,@action,@remoteAddr,@protocol,@program,
                       COALESCE((SELECT created FROM fw_state WHERE name=@name),@now))
                """,
                new { name, direction, action, remoteAddr, protocol, program, now });
        }
    }

    public void RemoveFwState(string name)
    {
        lock (_gate)
        {
            _conn.Execute("DELETE FROM fw_state WHERE name=@name", new { name });
        }
    }

    public IReadOnlySet<string> GetFwStateNames()
    {
        lock (_gate)
        {
            return _conn.Query<string>("SELECT name FROM fw_state").ToHashSet(StringComparer.Ordinal);
        }
    }

    // ─── Rule groups (NET-103): assign HG_ rules to named toggleable groups ───

    /// <summary>Assign a rule to a group (idempotent). Empty group removes all of the rule's group memberships.</summary>
    public void AssignRuleToGroup(string ruleName, string group)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
        lock (_gate)
        {
            if (string.IsNullOrWhiteSpace(group))
            {
                _conn.Execute("DELETE FROM rule_groups WHERE rule_name=@r", new { r = ruleName });
                return;
            }

            _conn.Execute("INSERT OR IGNORE INTO rule_groups(grp,rule_name) VALUES(@g,@r)",
                new { g = group.Trim(), r = ruleName });
        }
    }

    /// <summary>Remove a whole group (its rule memberships; the rules themselves stay).</summary>
    public void RemoveRuleGroup(string group)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(group);
        lock (_gate)
        {
            _conn.Execute("DELETE FROM rule_groups WHERE grp=@g", new { g = group.Trim() });
        }
    }

    /// <summary>Rule names in a group.</summary>
    public IReadOnlyList<string> GetRulesInGroup(string group)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(group);
        lock (_gate)
        {
            return _conn.Query<string>("SELECT rule_name FROM rule_groups WHERE grp=@g ORDER BY rule_name",
                new { g = group.Trim() }).ToList();
        }
    }

    /// <summary>All group→rule-name memberships (for listing + portable-policy export).</summary>
    public IReadOnlyList<(string Group, string RuleName)> GetRuleGroups()
    {
        lock (_gate)
        {
            return _conn.Query<(string, string)>(
                "SELECT grp, rule_name FROM rule_groups ORDER BY grp, rule_name").ToList();
        }
    }

    /// <summary>Full tracked-rule rows, for the Secure-Rules tamper reconcile.</summary>
    public IReadOnlyList<FwStateRow> GetFwState()
    {
        lock (_gate)
        {
            return _conn.Query<FwStateRow>(
                """
                SELECT name AS Name, direction AS Direction, action AS Action,
                       remote_addr AS RemoteAddr, protocol AS Protocol, program AS Program
                FROM fw_state
                """).ToList();
        }
    }

    // ─── Adopted (imported) Windows Firewall rules (NET-095) ─────────────────

    /// <summary>
    /// Record existing (non-HG_) Windows Firewall rules HostsGuard adopts into its
    /// view. Non-destructive: the live WF rules are never changed — this only
    /// remembers them so they persist in HostsGuard's model, tagged distinctly.
    /// Returns the number of newly-adopted rows.
    /// </summary>
    public int AdoptRules(IEnumerable<(string Name, string Direction, string Action, string RemoteAddr, string Protocol, string Program, bool Enabled)> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var added = 0;
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            foreach (var r in rows)
            {
                if (string.IsNullOrWhiteSpace(r.Name))
                {
                    continue;
                }

                added += _conn.Execute(
                    """
                    INSERT INTO adopted_rules(name,direction,action,remote_addr,protocol,program,enabled,adopted_at)
                    VALUES(@Name,@Direction,@Action,@RemoteAddr,@Protocol,@Program,@Enabled,@now)
                    ON CONFLICT(name) DO UPDATE SET
                        direction=excluded.direction, action=excluded.action, remote_addr=excluded.remote_addr,
                        protocol=excluded.protocol, program=excluded.program, enabled=excluded.enabled
                    """,
                    new { r.Name, r.Direction, r.Action, r.RemoteAddr, r.Protocol, r.Program, Enabled = r.Enabled ? 1 : 0, now }, tx);
            }

            tx.Commit();
        }

        return added;
    }

    public IReadOnlySet<string> GetAdoptedRuleNames()
    {
        lock (_gate)
        {
            return _conn.Query<string>("SELECT name FROM adopted_rules").ToHashSet(StringComparer.Ordinal);
        }
    }

    public void RemoveAdoptedRule(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        lock (_gate)
        {
            _conn.Execute("DELETE FROM adopted_rules WHERE name=@name", new { name });
        }
    }

    // ─── Log ──────────────────────────────────────────────────────────────────

    // ─── Stats ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Paged/filterable persistent event ledger. Filters, including derived
    /// taxonomy category, run in SQLite before paging.
    /// </summary>
    public EventLogPage GetEvents(EventLogFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var limit = Math.Clamp(filter.Limit <= 0 ? 200 : filter.Limit, 1, 2000);
        var offset = Math.Max(0, filter.Offset);
        var (where, args) = BuildEventWhere(filter);

        lock (_gate)
        {
            var total = _conn.ExecuteScalar<int>($"SELECT COUNT(*) FROM log{where}", args);
            args.Add("limit", limit);
            args.Add("offset", offset);
            var rows = _conn.Query<EventLogRowRaw>(
                    $"SELECT id, ts, domain, action, process, details, reason FROM log{where} ORDER BY ts DESC, id DESC LIMIT @limit OFFSET @offset",
                    args)
                .Select(ToEventLogRow)
                .ToList();
            return new EventLogPage(rows, total);
        }
    }

    private static (string Where, DynamicParameters Args) BuildEventWhere(EventLogFilter filter)
    {
        var clauses = new List<string>();
        var args = new DynamicParameters();

        AddLike("search", filter.Search,
            "(domain LIKE @search ESCAPE '\\' OR action LIKE @search ESCAPE '\\' OR process LIKE @search ESCAPE '\\' OR details LIKE @search ESCAPE '\\' OR reason LIKE @search ESCAPE '\\')");
        if (!string.IsNullOrWhiteSpace(filter.Since))
        {
            clauses.Add("ts >= @since");
            args.Add("since", filter.Since.Trim());
        }

        if (!string.IsNullOrWhiteSpace(filter.Until))
        {
            clauses.Add("ts <= @until");
            args.Add("until", filter.Until.Trim());
        }

        AddExact("action", filter.Action, "action");
        AddExact("reason", filter.Reason, "reason");
        AddLike("domain", filter.Domain, "domain LIKE @domain ESCAPE '\\'");
        AddLike("process", filter.Process, "process LIKE @process ESCAPE '\\'");
        AddCategory(filter.Category);

        return (clauses.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", clauses), args);

        void AddLike(string name, string? value, string clause)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            clauses.Add(clause);
            args.Add(name, "%" + EscapeLike(value.Trim()) + "%");
        }

        void AddExact(string name, string? value, string column)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            clauses.Add($"LOWER({column}) = LOWER(@{name})");
            args.Add(name, value.Trim());
        }

        void AddCategory(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            clauses.Add($"{EventCategorySql} = @category");
            args.Add("category", value.Trim().ToLowerInvariant());
        }
    }

    private static readonly string EventCategorySql =
        $"""
        CASE
            WHEN action IS NULL OR action = '' THEN '{EventTaxonomy.Categories.Other}'
            WHEN LOWER(action) LIKE 'consent%' OR LOWER(action) IN ('{EventTaxonomy.ModeChanged}', '{EventTaxonomy.PostureRestoredOnStop}') THEN '{EventTaxonomy.Categories.Consent}'
            WHEN LOWER(action) LIKE 'fw\_%' ESCAPE '\' OR LOWER(action) IN ('{EventTaxonomy.LockdownOn}', '{EventTaxonomy.LockdownOff}') THEN '{EventTaxonomy.Categories.Firewall}'
            WHEN LOWER(action) IN ('{EventTaxonomy.Blocked}', '{EventTaxonomy.Whitelisted}', '{EventTaxonomy.RawEdit}', '{EventTaxonomy.AclHardened}', '{EventTaxonomy.BackupRestored}') THEN '{EventTaxonomy.Categories.Hosts}'
            WHEN LOWER(action) = '{EventTaxonomy.ExclusionAdded}' OR LOWER(action) LIKE '%defender%' THEN '{EventTaxonomy.Categories.Defender}'
            WHEN LOWER(action) = '{EventTaxonomy.BundleExport}' OR LOWER(action) LIKE 'support%' THEN '{EventTaxonomy.Categories.Support}'
            WHEN LOWER(action) LIKE '%doh%' OR LOWER(action) LIKE '%dns%' OR LOWER(action) LIKE '%resolver%' THEN '{EventTaxonomy.Categories.Dns}'
            WHEN LOWER(action) LIKE '%blocklist%' OR LOWER(action) LIKE '%allowlist%' OR LOWER(action) LIKE '%list%' THEN '{EventTaxonomy.Categories.Lists}'
            WHEN LOWER(action) LIKE '%profile%' OR LOWER(action) LIKE '%schedule%' OR LOWER(action) LIKE '%lock%' OR LOWER(action) = 'imported' THEN '{EventTaxonomy.Categories.Policy}'
            ELSE '{EventTaxonomy.Categories.Other}'
        END
        """;

    private static string EscapeLike(string value) => value
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("%", "\\%", StringComparison.Ordinal)
        .Replace("_", "\\_", StringComparison.Ordinal);

    private static EventLogRow ToEventLogRow(EventLogRowRaw row)
        => new(
            row.Id,
            row.Ts ?? string.Empty,
            row.Domain ?? string.Empty,
            row.Action ?? string.Empty,
            row.Process ?? string.Empty,
            row.Details ?? string.Empty,
            row.Reason ?? string.Empty,
            EventTaxonomy.Category(row.Action));

    private sealed record EventLogRowRaw(
        long Id, string? Ts, string? Domain, string? Action, string? Process, string? Details, string? Reason);


}
