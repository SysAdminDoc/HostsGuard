using Dapper;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
    private static readonly (string Type, string Label, bool Surface)[] DefaultAlertTypes =
    {
        ("binary_identity", "Binary identity changes", true),
        ("threat_hit", "Threat-intel hits", true),
        ("hosts_tamper", "Hosts tamper", true),
        ("kill_switch", "VPN kill-switch", true),
        ("firewall_drift", "Firewall drift", true),
        ("wfp_external_filter", "External WFP blocks", true),
        ("unknown_lan", "Unknown LAN / gateway", true),
        ("usage_budget", "Usage budget alerts", true),
        ("dns_rebind", "DNS rebinding / out-of-scope answers", true),
        ("suspicious_domain", "Algorithmic / DGA-looking domains", true),
        ("port_scan", "Blocked inbound port scans", true),
        // Opt-in (off by default): a first-contact signal is high-volume, so it
        // only records/surfaces once the user enables the type.
        ("newly_observed_domain", "Newly observed domains", false),
        // Opt-in (off by default): a process talking DNS directly (port 53 to a
        // public resolver, or a known DoH endpoint) bypasses the system resolver.
        ("dns_bypass", "Apps bypassing system DNS", false),
    };

    /// <summary>Whether alerts of <paramref name="type"/> currently surface (opt-in gating for high-volume types).</summary>
    public bool IsAlertTypeSurfaced(string type)
    {
        type = CleanToken(type, string.Empty);
        if (type.Length == 0)
        {
            return false;
        }

        lock (_gate)
        {
            EnsureAlertTypeNoLock(type);
            return AlertTypeSurfaceNoLock(type);
        }
    }

    public long AddAlert(
        string type,
        string severity,
        string title,
        string subject,
        string details,
        string action = "",
        string process = "",
        long sourceEventId = 0)
    {
        type = CleanToken(type, "general");
        severity = CleanToken(severity, "info").ToLowerInvariant();
        title = CleanText(title, Humanize(type));
        subject = CleanText(subject, type);
        details = CleanText(details, string.Empty);
        action = CleanToken(action, string.Empty);
        process = CleanText(process, string.Empty);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);

        lock (_gate)
        {
            EnsureAlertTypeNoLock(type);
            var surfaced = AlertTypeSurfaceNoLock(type);
            var existing = _conn.QueryFirstOrDefault<long?>(
                """
                SELECT id FROM alerts
                WHERE is_read=0 AND type=@type AND subject=@subject AND action=@action
                ORDER BY id DESC LIMIT 1
                """,
                new { type, subject, action });
            if (existing is { } id)
            {
                _conn.Execute(
                    """
                    UPDATE alerts
                    SET updated=@now, severity=@severity, title=@title, details=@details,
                        process=@process, source_event_id=@sourceEventId, surfaced=@surfaced
                    WHERE id=@id
                    """,
                    new { id, now, severity, title, details, process, sourceEventId, surfaced = surfaced ? 1 : 0 });
                return id;
            }

            _conn.Execute(
                """
                INSERT INTO alerts(created,updated,type,severity,title,subject,details,action,process,source_event_id,is_read,surfaced)
                VALUES(@now,@now,@type,@severity,@title,@subject,@details,@action,@process,@sourceEventId,0,@surfaced)
                """,
                new { now, type, severity, title, subject, details, action, process, sourceEventId, surfaced = surfaced ? 1 : 0 });
            return _conn.ExecuteScalar<long>("SELECT last_insert_rowid()");
        }
    }

    public AlertPage GetAlerts(AlertFilter filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var limit = Math.Clamp(filter.Limit <= 0 ? 200 : filter.Limit, 1, 2000);
        var offset = Math.Max(0, filter.Offset);
        var clauses = new List<string>();
        var args = new DynamicParameters();
        if (!filter.IncludeRead)
        {
            clauses.Add("is_read=0");
        }

        if (filter.SurfaceOnly)
        {
            clauses.Add("surfaced=1");
        }

        if (!string.IsNullOrWhiteSpace(filter.Type))
        {
            clauses.Add("type=@type");
            args.Add("type", filter.Type.Trim());
        }

        var where = clauses.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", clauses);
        lock (_gate)
        {
            var total = _conn.ExecuteScalar<int>($"SELECT COUNT(*) FROM alerts{where}", args);
            var unread = _conn.ExecuteScalar<int>("SELECT COUNT(*) FROM alerts WHERE is_read=0 AND surfaced=1");
            args.Add("limit", limit);
            args.Add("offset", offset);
            var rows = _conn.Query<AlertRowRaw>(
                    $"SELECT id, created, updated, type, severity, title, subject, details, action, process, is_read AS IsRead, surfaced AS Surfaced FROM alerts{where} ORDER BY is_read ASC, updated DESC, id DESC LIMIT @limit OFFSET @offset",
                    args)
                .Select(ToAlertRow)
                .ToList();
            return new AlertPage(rows, total, unread);
        }
    }

    public int AckAlerts(IEnumerable<long> ids, bool all = false, string? type = null)
    {
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        var cleanIds = ids.Where(id => id > 0).Distinct().ToArray();
        lock (_gate)
        {
            if (all)
            {
                return string.IsNullOrWhiteSpace(type)
                    ? _conn.Execute("UPDATE alerts SET is_read=1, updated=@now WHERE is_read=0", new { now })
                    : _conn.Execute("UPDATE alerts SET is_read=1, updated=@now WHERE is_read=0 AND type=@type", new { now, type = type.Trim() });
            }

            if (cleanIds.Length == 0)
            {
                return 0;
            }

            return _conn.Execute("UPDATE alerts SET is_read=1, updated=@now WHERE is_read=0 AND id IN @ids", new { now, ids = cleanIds });
        }
    }

    public IReadOnlyList<AlertTypeRow> GetAlertTypes()
    {
        lock (_gate)
        {
            foreach (var (type, _, _) in DefaultAlertTypes)
            {
                EnsureAlertTypeNoLock(type);
            }

            return _conn.Query<AlertTypeRowRaw>(
                    """
                    SELECT s.type, s.label, s.surface,
                           COALESCE(SUM(CASE WHEN a.is_read=0 THEN 1 ELSE 0 END), 0) AS unread
                    FROM alert_type_settings s
                    LEFT JOIN alerts a ON a.type=s.type
                    GROUP BY s.type, s.label, s.surface
                    ORDER BY s.label
                    """)
                .Select(r => new AlertTypeRow(r.Type ?? string.Empty, r.Label ?? Humanize(r.Type ?? string.Empty), r.Surface != 0, (int)r.Unread))
                .ToList();
        }
    }

    public void SetAlertTypeSurface(string type, bool surface)
    {
        type = CleanToken(type, string.Empty);
        if (type.Length == 0)
        {
            return;
        }

        lock (_gate)
        {
            EnsureAlertTypeNoLock(type);
            _conn.Execute(
                "UPDATE alert_type_settings SET surface=@surface WHERE type=@type",
                new { type, surface = surface ? 1 : 0 });
            _conn.Execute(
                "UPDATE alerts SET surfaced=@surface WHERE type=@type AND is_read=0",
                new { type, surface = surface ? 1 : 0 });
        }
    }

    private void EnsureAlertTypeNoLock(string type)
    {
        var known = DefaultAlertTypes.FirstOrDefault(t => string.Equals(t.Type, type, StringComparison.Ordinal));
        var label = known.Label ?? Humanize(type);
        var surface = known.Type is null || known.Surface ? 1 : 0;
        _conn.Execute(
            "INSERT OR IGNORE INTO alert_type_settings(type,label,surface) VALUES(@type,@label,@surface)",
            new { type, label, surface });
    }

    private bool AlertTypeSurfaceNoLock(string type)
        => _conn.ExecuteScalar<int?>("SELECT surface FROM alert_type_settings WHERE type=@type", new { type }) != 0;

    private static AlertRow ToAlertRow(AlertRowRaw row)
        => new(
            row.Id,
            row.Created ?? string.Empty,
            row.Updated ?? string.Empty,
            row.Type ?? string.Empty,
            row.Severity ?? string.Empty,
            row.Title ?? string.Empty,
            row.Subject ?? string.Empty,
            row.Details ?? string.Empty,
            row.Action ?? string.Empty,
            row.Process ?? string.Empty,
            row.IsRead != 0,
            row.Surfaced != 0);

    private static string CleanToken(string value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private static string CleanText(string value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private static string Humanize(string type)
        => string.Join(" ", (type ?? string.Empty).Split('_', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    private sealed record AlertRowRaw(
        long Id,
        string? Created,
        string? Updated,
        string? Type,
        string? Severity,
        string? Title,
        string? Subject,
        string? Details,
        string? Action,
        string? Process,
        long IsRead,
        long Surfaced);

    private sealed record AlertTypeRowRaw(string? Type, string? Label, long Surface, long Unread);
}
