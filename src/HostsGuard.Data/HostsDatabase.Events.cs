using Dapper;
using HostsGuard.Core;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
    public void LogEvent(
        string domain,
        string action,
        string process = "",
        string details = "",
        string? reason = null,
        WfpAuditProvenance? provenance = null,
        string? matchedSource = null)
    {
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        provenance ??= WfpAuditProvenance.Empty;
        var canonicalReason = Reasons.Canonical(reason, "", action, details);
        lock (_gate)
        {
            ThrowIfDisposed();
            var decidingSource = ResolveMatchedSource(
                domain, action, details, canonicalReason, provenance, matchedSource);
            _conn.Execute(
                """
                INSERT INTO log(
                    ts,domain,action,process,details,reason,
                    filter_runtime_id,filter_origin,layer_name,layer_runtime_id,interface_index,interface_name,
                    matched_source)
                VALUES(
                    @now,@domain,@action,@process,@details,@reason,
                    @filterRuntimeId,@filterOrigin,@layerName,@layerRuntimeId,@interfaceIndex,@interfaceName,
                    @matchedSource)
                """,
                new
                {
                    now,
                    domain,
                    action,
                    process,
                    details,
                    reason = canonicalReason,
                    filterRuntimeId = provenance.FilterRuntimeId,
                    filterOrigin = provenance.FilterOrigin,
                    layerName = provenance.LayerName,
                    layerRuntimeId = provenance.LayerRuntimeId,
                    interfaceIndex = provenance.InterfaceIndex,
                    interfaceName = provenance.InterfaceName,
                    matchedSource = decidingSource,
                });
        }
    }

    private string ResolveMatchedSource(
        string domain,
        string action,
        string details,
        string canonicalReason,
        WfpAuditProvenance provenance,
        string? requested)
    {
        if (!string.IsNullOrWhiteSpace(requested))
        {
            return requested.Trim();
        }

        if (!IsBlockDecision(action))
        {
            return string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(provenance.FilterOrigin))
        {
            return provenance.FilterOrigin.Trim();
        }

        var managedSource = _conn.ExecuteScalar<string?>(
            "SELECT source FROM domains WHERE domain=@domain",
            new { domain = (domain ?? string.Empty).Trim().ToLowerInvariant() });
        if (!string.IsNullOrWhiteSpace(managedSource))
        {
            return managedSource;
        }

        var list = _conn.ExecuteScalar<string?>(
            "SELECT list FROM list_index WHERE domain=@domain ORDER BY list LIMIT 1",
            new { domain = (domain ?? string.Empty).Trim().ToLowerInvariant() });
        if (!string.IsNullOrWhiteSpace(list))
        {
            return $"list:{list}";
        }

        if (action.Equals(EventTaxonomy.FwBlocked, StringComparison.Ordinal)
            && details.TrimStart().StartsWith("HG_", StringComparison.Ordinal))
        {
            return details.Trim();
        }

        return canonicalReason == "unknown" ? action.Trim() : canonicalReason;
    }

    private static bool IsBlockDecision(string? action)
    {
        var value = (action ?? string.Empty).Trim().ToLowerInvariant();
        return value == EventTaxonomy.Blocked
            || value == EventTaxonomy.FwBlocked
            || value == EventTaxonomy.ConsentBlock
            || value == "temp_blocked"
            || value.EndsWith("_blocked", StringComparison.Ordinal)
            || value.EndsWith("_block", StringComparison.Ordinal);
    }

    public IReadOnlyList<LogEventRow> GetLog(int limit = 200)
    {
        lock (_gate)
        {
            return _conn.Query<EventLogRowRaw>(
                """
                SELECT
                    id AS Id,
                    ts AS Ts,
                    domain AS Domain,
                    action AS Action,
                    process AS Process,
                    details AS Details,
                    reason AS Reason,
                    filter_runtime_id AS FilterRuntimeId,
                    filter_origin AS FilterOrigin,
                    layer_name AS LayerName,
                    layer_runtime_id AS LayerRuntimeId,
                    CAST(COALESCE(interface_index, 0) AS INTEGER) AS InterfaceIndex,
                    interface_name AS InterfaceName,
                    matched_source AS MatchedSource
                FROM log
                ORDER BY ts DESC
                LIMIT @limit
                """,
                new { limit })
                .Select(ToLogEventRow)
                .ToList();
        }
    }

    private static LogEventRow ToLogEventRow(EventLogRowRaw row)
        => new(
            row.Ts ?? string.Empty,
            row.Domain ?? string.Empty,
            row.Action ?? string.Empty,
            row.Process ?? string.Empty,
            row.Details ?? string.Empty,
            row.Reason ?? string.Empty,
            row.FilterRuntimeId ?? string.Empty,
            row.FilterOrigin ?? string.Empty,
            row.LayerName ?? string.Empty,
            row.LayerRuntimeId ?? string.Empty,
            ToInterfaceIndex(row.InterfaceIndex),
            row.InterfaceName ?? string.Empty,
            row.MatchedSource ?? string.Empty);

}
