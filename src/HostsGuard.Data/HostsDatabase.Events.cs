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
        WfpAuditProvenance? provenance = null)
    {
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        provenance ??= WfpAuditProvenance.Empty;
        lock (_gate)
        {
            ThrowIfDisposed();
            _conn.Execute(
                """
                INSERT INTO log(
                    ts,domain,action,process,details,reason,
                    filter_runtime_id,filter_origin,layer_name,layer_runtime_id,interface_index,interface_name)
                VALUES(
                    @now,@domain,@action,@process,@details,@reason,
                    @filterRuntimeId,@filterOrigin,@layerName,@layerRuntimeId,@interfaceIndex,@interfaceName)
                """,
                new
                {
                    now,
                    domain,
                    action,
                    process,
                    details,
                    reason = Reasons.Canonical(reason, "", action, details),
                    filterRuntimeId = provenance.FilterRuntimeId,
                    filterOrigin = provenance.FilterOrigin,
                    layerName = provenance.LayerName,
                    layerRuntimeId = provenance.LayerRuntimeId,
                    interfaceIndex = provenance.InterfaceIndex,
                    interfaceName = provenance.InterfaceName,
                });
        }
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
                    interface_name AS InterfaceName
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
            row.InterfaceName ?? string.Empty);

}
