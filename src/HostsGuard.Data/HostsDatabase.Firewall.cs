using Dapper;
using HostsGuard.Core;
using System.Security.Cryptography;
using System.Text;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
    private const string FirewallSnapshotInitializedKey = "firewall_snapshot_initialized";

    // ─── Firewall state (drift tracking) ──────────────────────────────────────

    /// <summary>Track a HostsGuard-created rule so drift (deleted-behind-our-back) is detectable.</summary>
    public void UpsertFwState(
        string name,
        string direction,
        string action,
        string remoteAddr,
        string protocol,
        string program,
        string remotePorts = "Any",
        string localPorts = "Any",
        string serviceName = "",
        string interfaces = "Any",
        string packageFamilyName = "",
        string packageSid = "",
        string packageDisplayName = "",
        string packageFullName = "",
        string packageBinaries = "")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT OR REPLACE INTO fw_state(
                    name,direction,action,remote_addr,protocol,program,remote_ports,local_ports,service_name,interfaces,
                    package_family_name,package_sid,package_display_name,package_full_name,package_binaries,created)
                VALUES(@name,@direction,@action,@remoteAddr,@protocol,@program,@remotePorts,@localPorts,@serviceName,@interfaces,
                       @packageFamilyName,@packageSid,@packageDisplayName,@packageFullName,@packageBinaries,
                       COALESCE((SELECT created FROM fw_state WHERE name=@name),@now))
                """,
                new
                {
                    name,
                    direction,
                    action,
                    remoteAddr,
                    protocol,
                    program,
                    remotePorts,
                    localPorts,
                    serviceName,
                    interfaces,
                    packageFamilyName,
                    packageSid,
                    packageDisplayName,
                    packageFullName,
                    packageBinaries,
                    now,
                });
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
            ThrowIfDisposed();
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
            ThrowIfDisposed();
            return _conn.Query<FwStateRow>(
                """
                SELECT name AS Name, direction AS Direction, action AS Action,
                       remote_addr AS RemoteAddr, protocol AS Protocol, program AS Program,
                       remote_ports AS RemotePorts, local_ports AS LocalPorts, service_name AS ServiceName,
                       interfaces AS Interfaces, package_family_name AS PackageFamilyName,
                       package_sid AS PackageSid, package_display_name AS PackageDisplayName,
                       package_full_name AS PackageFullName, package_binaries AS PackageBinaries
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
    /// <summary>
    /// Snapshot every live Windows Firewall rule, returning changes since the
    /// prior baseline. The first call seeds silently; later calls report
    /// added/changed/vanished rules without mutating the live firewall.
    /// </summary>
    public IReadOnlyList<FirewallRuleDriftRow> SnapshotFirewallRules(IEnumerable<FwRule> rules, DateTime? observedAt = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var now = (observedAt ?? DateTime.Now).ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var live = rules
            .Where(r => !string.IsNullOrWhiteSpace(r.Name))
            .GroupBy(r => r.Name, StringComparer.Ordinal)
            .Select(g => g.First())
            .ToDictionary(r => r.Name, StringComparer.Ordinal);

        var diffs = new List<FirewallRuleDriftRow>();
        lock (_gate)
        {
            var initialized = _conn.ExecuteScalar<string>(
                "SELECT value FROM meta WHERE key=@key",
                new { key = FirewallSnapshotInitializedKey }) == "1";
            var existing = _conn.Query<FirewallRuleSnapshotRow>(
                    """
                    SELECT name AS Name, direction AS Direction, action AS Action, enabled AS Enabled,
                           remote_addr AS RemoteAddr, protocol AS Protocol, program AS Program, source AS Source,
                           remote_ports AS RemotePorts, local_ports AS LocalPorts, service_name AS ServiceName,
                           interfaces AS Interfaces, package_family_name AS PackageFamilyName,
                           package_sid AS PackageSid, package_display_name AS PackageDisplayName,
                           package_full_name AS PackageFullName, package_binaries AS PackageBinaries, hash AS Hash,
                           present AS Present, first_seen AS FirstSeen, last_seen AS LastSeen,
                           changed_at AS ChangedAt, change_kind AS ChangeKind, change_detail AS ChangeDetail
                    FROM firewall_rule_snapshot
                    """)
                .ToDictionary(r => r.Name, StringComparer.Ordinal);

            using var tx = _conn.BeginTransaction();
            foreach (var rule in live.Values)
            {
                var hash = HashFirewallRule(rule);
                if (!existing.TryGetValue(rule.Name, out var old))
                {
                    var kind = initialized ? "added" : string.Empty;
                    var detail = initialized ? $"added {Describe(rule)}" : string.Empty;
                    _conn.Execute(
                        """
                        INSERT INTO firewall_rule_snapshot(
                            name,direction,action,enabled,remote_addr,protocol,program,source,remote_ports,local_ports,service_name,interfaces,
                            package_family_name,package_sid,package_display_name,package_full_name,package_binaries,
                            hash,present,first_seen,last_seen,changed_at,change_kind,change_detail)
                        VALUES(@Name,@Direction,@Action,@Enabled,@RemoteAddr,@Protocol,@Program,@Source,@RemotePorts,@LocalPorts,@ServiceName,@Interfaces,
                               @PackageFamilyName,@PackageSid,@PackageDisplayName,@PackageFullName,@PackageBinaries,
                               @Hash,1,@now,@now,@changedAt,@ChangeKind,@ChangeDetail)
                        """,
                        SnapshotParams(rule, hash, now, initialized ? now : string.Empty, kind, detail), tx);
                    if (initialized)
                    {
                        diffs.Add(ToDrift(rule, kind, detail));
                    }

                    continue;
                }

                if (!old.Present || !string.Equals(old.Hash, hash, StringComparison.Ordinal))
                {
                    var kind = old.Present ? "changed" : "added";
                    var detail = kind == "changed" ? DescribeChanges(old, rule) : $"added {Describe(rule)}";
                    _conn.Execute(
                        """
                        UPDATE firewall_rule_snapshot
                        SET direction=@Direction, action=@Action, enabled=@Enabled, remote_addr=@RemoteAddr,
                            protocol=@Protocol, program=@Program, source=@Source, remote_ports=@RemotePorts,
                            local_ports=@LocalPorts, service_name=@ServiceName, interfaces=@Interfaces,
                            package_family_name=@PackageFamilyName, package_sid=@PackageSid,
                            package_display_name=@PackageDisplayName, package_full_name=@PackageFullName,
                            package_binaries=@PackageBinaries,
                            hash=@Hash, present=1, last_seen=@now,
                            changed_at=@changedAt, change_kind=@ChangeKind, change_detail=@ChangeDetail
                        WHERE name=@Name
                        """,
                        SnapshotParams(rule, hash, now, now, kind, detail), tx);
                    if (initialized)
                    {
                        diffs.Add(ToDrift(rule, kind, detail));
                    }
                }
                else
                {
                    _conn.Execute(
                        "UPDATE firewall_rule_snapshot SET present=1, last_seen=@now WHERE name=@Name",
                        new { rule.Name, now }, tx);
                }
            }

            foreach (var old in existing.Values.Where(r => r.Present && !live.ContainsKey(r.Name)))
            {
                var detail = $"vanished {Describe(old)}";
                _conn.Execute(
                    """
                    UPDATE firewall_rule_snapshot
                    SET present=0, changed_at=@now, change_kind='vanished', change_detail=@detail
                    WHERE name=@Name
                    """,
                    new { old.Name, now, detail }, tx);
                if (initialized)
                {
                    diffs.Add(ToDrift(old, "vanished", detail));
                }
            }

            _conn.Execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(@key,'1')",
                new { key = FirewallSnapshotInitializedKey }, tx);
            tx.Commit();
        }

        return diffs;
    }

    public IReadOnlyList<FirewallRuleSnapshotRow> GetFirewallRuleSnapshots()
    {
        lock (_gate)
        {
            return _conn.Query<FirewallRuleSnapshotRow>(
                """
                SELECT name AS Name, direction AS Direction, action AS Action, enabled AS Enabled,
                       remote_addr AS RemoteAddr, protocol AS Protocol, program AS Program, source AS Source,
                       remote_ports AS RemotePorts, local_ports AS LocalPorts, service_name AS ServiceName,
                       interfaces AS Interfaces, package_family_name AS PackageFamilyName,
                       package_sid AS PackageSid, package_display_name AS PackageDisplayName,
                       package_full_name AS PackageFullName, package_binaries AS PackageBinaries, hash AS Hash,
                       present AS Present, first_seen AS FirstSeen, last_seen AS LastSeen,
                       changed_at AS ChangedAt, change_kind AS ChangeKind, change_detail AS ChangeDetail
                FROM firewall_rule_snapshot
                ORDER BY name
                """).ToList();
        }
    }

    private static object SnapshotParams(FwRule rule, string hash, string now, string changedAt, string changeKind, string changeDetail) => new
    {
        rule.Name,
        Direction = Clean(rule.Direction),
        Action = Clean(rule.Action),
        Enabled = rule.Enabled ? 1 : 0,
        RemoteAddr = Clean(rule.RemoteAddr),
        Protocol = Clean(rule.Protocol),
        Program = Clean(rule.Program),
        Source = Clean(rule.Source),
        RemotePorts = Clean(rule.RemotePorts),
        LocalPorts = Clean(rule.LocalPorts),
        ServiceName = Clean(rule.ServiceName),
        Interfaces = Clean(rule.Interfaces),
        PackageFamilyName = Clean(rule.PackageFamilyName),
        PackageSid = Clean(rule.PackageSid),
        PackageDisplayName = Clean(rule.PackageDisplayName),
        PackageFullName = Clean(rule.PackageFullName),
        PackageBinaries = Clean(rule.PackageBinaries),
        Hash = hash,
        now,
        changedAt,
        ChangeKind = changeKind,
        ChangeDetail = changeDetail,
    };

    private static string HashFirewallRule(FwRule rule)
    {
        var canonical = string.Join('\n',
            Clean(rule.Direction),
            Clean(rule.Action),
            rule.Enabled ? "1" : "0",
            Clean(rule.RemoteAddr),
            Clean(rule.Protocol),
            Clean(rule.Program),
            Clean(rule.Source),
            Clean(rule.RemotePorts),
            Clean(rule.LocalPorts),
            Clean(rule.ServiceName),
            Clean(rule.Interfaces),
            Clean(rule.PackageFamilyName),
            Clean(rule.PackageSid),
            Clean(rule.PackageDisplayName),
            Clean(rule.PackageFullName),
            Clean(rule.PackageBinaries));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    private static FirewallRuleDriftRow ToDrift(FwRule rule, string kind, string details) => new(
        rule.Name,
        kind,
        Clean(rule.Source),
        Clean(rule.Direction),
        Clean(rule.Action),
        rule.Enabled,
        Clean(rule.RemoteAddr),
        Clean(rule.Protocol),
        Clean(rule.Program),
        Clean(rule.RemotePorts),
        Clean(rule.LocalPorts),
        Clean(rule.ServiceName),
        Clean(rule.Interfaces),
        Clean(rule.PackageFamilyName),
        Clean(rule.PackageSid),
        Clean(rule.PackageDisplayName),
        Clean(rule.PackageFullName),
        Clean(rule.PackageBinaries),
        details);

    private static FirewallRuleDriftRow ToDrift(FirewallRuleSnapshotRow row, string kind, string details) => new(
        row.Name,
        kind,
        Clean(row.Source),
        Clean(row.Direction),
        Clean(row.Action),
        row.Enabled,
        Clean(row.RemoteAddr),
        Clean(row.Protocol),
        Clean(row.Program),
        Clean(row.RemotePorts),
        Clean(row.LocalPorts),
        Clean(row.ServiceName),
        Clean(row.Interfaces),
        Clean(row.PackageFamilyName),
        Clean(row.PackageSid),
        Clean(row.PackageDisplayName),
        Clean(row.PackageFullName),
        Clean(row.PackageBinaries),
        details);

    private static string Describe(FwRule rule) =>
        $"{Clean(rule.Source)} {Clean(rule.Direction)} {Clean(rule.Action)} {(rule.Enabled ? "enabled" : "disabled")} " +
        $"{Clean(rule.Protocol)} remote={Clean(rule.RemoteAddr)} remotePorts={Clean(rule.RemotePorts)} localPorts={Clean(rule.LocalPorts)} program={Clean(rule.Program)} service={Clean(rule.ServiceName)} interfaces={Clean(rule.Interfaces)} package={Clean(rule.PackageFamilyName)}";

    private static string Describe(FirewallRuleSnapshotRow row) =>
        $"{Clean(row.Source)} {Clean(row.Direction)} {Clean(row.Action)} {(row.Enabled ? "enabled" : "disabled")} " +
        $"{Clean(row.Protocol)} remote={Clean(row.RemoteAddr)} remotePorts={Clean(row.RemotePorts)} localPorts={Clean(row.LocalPorts)} program={Clean(row.Program)} service={Clean(row.ServiceName)} interfaces={Clean(row.Interfaces)} package={Clean(row.PackageFamilyName)}";

    private static string DescribeChanges(FirewallRuleSnapshotRow old, FwRule current)
    {
        var changes = new List<string>();
        Add("direction", old.Direction, current.Direction);
        Add("action", old.Action, current.Action);
        Add("enabled", old.Enabled ? "on" : "off", current.Enabled ? "on" : "off");
        Add("remote", old.RemoteAddr, current.RemoteAddr);
        Add("protocol", old.Protocol, current.Protocol);
        Add("program", old.Program, current.Program);
        Add("remote ports", old.RemotePorts, current.RemotePorts);
        Add("local ports", old.LocalPorts, current.LocalPorts);
        Add("service", old.ServiceName, current.ServiceName);
        Add("interfaces", old.Interfaces, current.Interfaces);
        Add("package family", old.PackageFamilyName, current.PackageFamilyName);
        Add("package sid", old.PackageSid, current.PackageSid);
        Add("package display", old.PackageDisplayName, current.PackageDisplayName);
        Add("package full name", old.PackageFullName, current.PackageFullName);
        Add("package binaries", old.PackageBinaries, current.PackageBinaries);
        return changes.Count == 0 ? $"changed {Describe(current)}" : "changed " + string.Join("; ", changes);

        void Add(string label, string? before, string? after)
        {
            before = Clean(before);
            after = Clean(after);
            if (!string.Equals(before, after, StringComparison.Ordinal))
            {
                changes.Add($"{label}: {before} -> {after}");
            }
        }
    }

    private static string Clean(string? value) => (value ?? string.Empty).Trim();

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
                    $"""
                     SELECT id, ts, domain, action, process, details, reason,
                            filter_runtime_id AS FilterRuntimeId,
                            filter_origin AS FilterOrigin,
                            layer_name AS LayerName,
                            layer_runtime_id AS LayerRuntimeId,
                            CAST(COALESCE(interface_index, 0) AS INTEGER) AS InterfaceIndex,
                            interface_name AS InterfaceName
                     FROM log{where}
                     ORDER BY ts DESC, id DESC
                     LIMIT @limit OFFSET @offset
                     """,
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
            "(domain LIKE @search ESCAPE '\\' OR action LIKE @search ESCAPE '\\' OR process LIKE @search ESCAPE '\\' OR details LIKE @search ESCAPE '\\' OR reason LIKE @search ESCAPE '\\' OR filter_origin LIKE @search ESCAPE '\\' OR interface_name LIKE @search ESCAPE '\\')");
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
            WHEN LOWER(action) LIKE 'fw\_%' ESCAPE '\' OR LOWER(action) IN ('{EventTaxonomy.LockdownOn}', '{EventTaxonomy.LockdownOff}', '{EventTaxonomy.PortScan}') THEN '{EventTaxonomy.Categories.Firewall}'
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
            EventTaxonomy.Category(row.Action),
            row.FilterRuntimeId ?? string.Empty,
            row.FilterOrigin ?? string.Empty,
            row.LayerName ?? string.Empty,
            row.LayerRuntimeId ?? string.Empty,
            ToInterfaceIndex(row.InterfaceIndex),
            row.InterfaceName ?? string.Empty);

    private static int ToInterfaceIndex(object? value)
        => value switch
        {
            null => 0,
            int i => i,
            long l => (int)Math.Clamp(l, int.MinValue, int.MaxValue),
            byte[] bytes when bytes.Length == 0 => 0,
            byte[] bytes when long.TryParse(System.Text.Encoding.UTF8.GetString(bytes), out var parsed)
                => (int)Math.Clamp(parsed, int.MinValue, int.MaxValue),
            string s when long.TryParse(s, out var parsed) => (int)Math.Clamp(parsed, int.MinValue, int.MaxValue),
            _ => 0,
        };

    private sealed class EventLogRowRaw
    {
        public long Id { get; set; }

        public string? Ts { get; set; }

        public string? Domain { get; set; }

        public string? Action { get; set; }

        public string? Process { get; set; }

        public string? Details { get; set; }

        public string? Reason { get; set; }

        public string? FilterRuntimeId { get; set; }

        public string? FilterOrigin { get; set; }

        public string? LayerName { get; set; }

        public string? LayerRuntimeId { get; set; }

        public object? InterfaceIndex { get; set; }

        public string? InterfaceName { get; set; }
    }


}
