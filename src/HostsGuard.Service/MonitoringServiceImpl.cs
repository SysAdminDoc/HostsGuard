using System.Globalization;
using System.Runtime.Versioning;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;

namespace HostsGuard.Service;

/// <summary>
/// Server-streaming live feeds plus the persistent connection-history and
/// per-app bandwidth queries (NET-070). Each watcher subscribes to the
/// in-process EventBus; the stream ends when the client disconnects. The
/// engines (ETW DNS, connection monitor, temp-allow scheduler) publish onto
/// the bus.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MonitoringServiceImpl : Monitoring.MonitoringBase
{
    private readonly ServiceState _state;

    public MonitoringServiceImpl(ServiceState state) => _state = state;

    public override Task WatchDns(Empty request, IServerStreamWriter<DnsEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    public override Task WatchConnections(Empty request, IServerStreamWriter<ConnectionEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    public override Task WatchEvents(Empty request, IServerStreamWriter<ActivityEvent> responseStream, ServerCallContext context)
        => Pump(responseStream, context);

    public override Task<ConnectionHistoryList> GetConnectionHistory(ConnectionHistoryRequest request, ServerCallContext context)
    {
        var rows = _state.Db.GetConnectionHistory(
            request.Limit > 0 ? request.Limit : 500,
            string.IsNullOrWhiteSpace(request.Search) ? null : request.Search,
            string.IsNullOrWhiteSpace(request.Since) ? null : request.Since);
        var list = new ConnectionHistoryList();
        foreach (var r in rows)
        {
            list.Rows.Add(new ConnectionHistoryRow
            {
                Ts = r.Ts,
                Process = r.Process,
                Pid = (int)r.Pid,
                Protocol = r.Protocol,
                RemoteAddr = r.RemoteAddr,
                RemotePort = (int)r.RemotePort,
                Country = r.Country,
                FwStatus = r.FwStatus,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<EventLogList> ListEvents(EventLogRequest request, ServerCallContext context)
    {
        var limit = Math.Clamp(request.Limit > 0 ? request.Limit : 200, 1, 2000);
        var offset = Math.Max(0, request.Offset);
        var page = _state.Db.GetEvents(new EventLogFilter(
            Limit: limit,
            Offset: offset,
            Search: Clean(request.Search),
            Since: Clean(request.Since),
            Until: Clean(request.Until),
            Action: Clean(request.Action),
            Reason: Clean(request.Reason),
            Domain: Clean(request.Domain),
            Process: Clean(request.Process),
            Category: Clean(request.Category)));

        var list = new EventLogList
        {
            Limit = limit,
            Offset = offset,
            Total = page.Total,
            Redacted = request.Redact,
        };
        foreach (var row in page.Rows)
        {
            list.Entries.Add(new EventLogEntry
            {
                Id = row.Id,
                Ts = row.Ts,
                Domain = request.Redact ? Redaction.RedactText(row.Domain) : row.Domain,
                Action = row.Action,
                Process = request.Redact ? Redaction.RedactScalar("program", row.Process) : row.Process,
                Details = request.Redact ? Redaction.RedactText(row.Details) : row.Details,
                Reason = row.Reason,
                Category = row.Category,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<AlertList> ListAlerts(AlertRequest request, ServerCallContext context)
    {
        var limit = Math.Clamp(request.Limit > 0 ? request.Limit : 200, 1, 2000);
        var offset = Math.Max(0, request.Offset);
        var page = _state.Db.GetAlerts(new AlertFilter(
            Limit: limit,
            Offset: offset,
            IncludeRead: request.IncludeRead,
            SurfaceOnly: !request.IncludeLogOnly,
            Type: Clean(request.Type)));

        var list = new AlertList
        {
            Total = page.Total,
            Unread = page.Unread,
        };
        foreach (var row in page.Rows)
        {
            list.Entries.Add(new AlertEntry
            {
                Id = row.Id,
                Created = row.Created,
                Updated = row.Updated,
                Type = row.Type,
                Severity = row.Severity,
                Title = row.Title,
                Subject = row.Subject,
                Details = row.Details,
                Action = row.Action,
                Process = row.Process,
                IsRead = row.IsRead,
                Surfaced = row.Surfaced,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> AckAlert(AlertAckRequest request, ServerCallContext context)
    {
        var changed = _state.Db.AckAlerts(request.Ids, request.All, Clean(request.Type));
        return Task.FromResult(new Ack { Ok = true, Message = $"acknowledged {changed} alert{(changed == 1 ? string.Empty : "s")}" });
    }

    public override Task<AlertTypeList> ListAlertTypes(Empty request, ServerCallContext context)
    {
        var list = new AlertTypeList();
        foreach (var row in _state.Db.GetAlertTypes())
        {
            list.Types_.Add(new AlertTypeEntry
            {
                Type = row.Type,
                Label = row.Label,
                Surface = row.Surface,
                Unread = row.Unread,
            });
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> SetAlertType(AlertTypeRequest request, ServerCallContext context)
    {
        var type = Clean(request.Type);
        if (type is null)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "alert type is required",
                ErrorCode = "hostsguard.error.v1/invalid_alert_type",
            });
        }

        _state.Db.SetAlertTypeSurface(type, request.Surface);
        return Task.FromResult(new Ack
        {
            Ok = true,
            Message = request.Surface ? $"{type} alerts will surface" : $"{type} alerts are log-only",
        });
    }

    public override Task<AppBandwidthList> GetAppBandwidth(BandwidthRequest request, ServerCallContext context)
        => Task.FromResult(BuildBandwidth(request, DateTime.Now));

    /// <summary>Aligned, zero-filled per-app series ending at <paramref name="now"/>'s minute.</summary>
    public AppBandwidthList BuildBandwidth(BandwidthRequest request, DateTime now)
    {
        var minutes = Math.Clamp(request.Minutes > 0 ? request.Minutes : 60, 5, 1440);
        var top = Math.Clamp(request.Top > 0 ? request.Top : 5, 1, 12);
        var origin = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0, now.Kind)
            .AddMinutes(-(minutes - 1));
        var rows = _state.Db.GetBandwidth(origin.ToString("yyyy-MM-ddTHH:mm", CultureInfo.InvariantCulture));

        var perProcess = new Dictionary<string, (long[] Buckets, long Sent, long Recv)>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            if (!DateTime.TryParseExact(row.Minute, "yyyy-MM-ddTHH:mm", CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var minute))
            {
                continue;
            }

            var slot = (int)(minute - origin).TotalMinutes;
            if (slot < 0 || slot >= minutes)
            {
                continue;
            }

            if (!perProcess.TryGetValue(row.Process, out var acc))
            {
                acc = (new long[minutes], 0, 0);
            }

            acc.Buckets[slot] += row.Sent + row.Recv;
            perProcess[row.Process] = (acc.Buckets, acc.Sent + row.Sent, acc.Recv + row.Recv);
        }

        var list = new AppBandwidthList { CountersActive = _state.Bandwidth?.CountersActive ?? false };
        foreach (var (process, acc) in perProcess
                     .OrderByDescending(kv => kv.Value.Sent + kv.Value.Recv)
                     .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                     .Take(top))
        {
            var series = new AppBandwidthSeries { Process = process, TotalSent = acc.Sent, TotalRecv = acc.Recv };
            series.Bytes.AddRange(acc.Buckets);
            list.Series.Add(series);
        }

        return list;
    }

    public override Task<HistorySettings> GetHistorySettings(Empty request, ServerCallContext context)
        => Task.FromResult(new HistorySettings { RetentionDays = _state.Db.HistoryRetentionDays });

    public override Task<Ack> SetHistorySettings(HistorySettings request, ServerCallContext context)
    {
        if (request.RetentionDays is < 1 or > 365)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = "retention must be 1-365 days",
                ErrorCode = "hostsguard.error.v1/invalid_argument",
            });
        }

        _state.Db.HistoryRetentionDays = request.RetentionDays;
        _state.Db.RunRetentionSweep(DateTime.Now, forceMaintenance: true);
        return Task.FromResult(new Ack { Ok = true, Message = $"history retention set to {request.RetentionDays} days" });
    }

    private async Task Pump<T>(IServerStreamWriter<T> stream, ServerCallContext context)
    {
        using var sub = _state.Bus.Subscribe<T>();
        try
        {
            await foreach (var item in sub.Reader.ReadAllAsync(context.CancellationToken))
            {
                await stream.WriteAsync(item, context.CancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Client went away — normal stream termination.
        }
    }

    private static string? Clean(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
