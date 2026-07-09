using System.Globalization;
using System.Net;
using System.Text.Encodings.Web;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;

namespace HostsGuard.Service;

internal static class TrafficProfileExporter
{
    public const string NoPayloadGuarantee =
        "Contains retained connection and event metadata only. It is not a packet capture and includes no PCAP frames, packet payloads, DNS message payloads, HTTP bodies, tokens, or full executable paths.";

    public static TrafficProfileExport Build(ServiceState state, TrafficProfileRequest request, DateTime now)
    {
        var snapshot = BuildSnapshot(state, request, now);
        var format = NormalizeFormat(request.Format);
        var content = format == "csv" ? BuildCsv(snapshot) : BuildJson(snapshot);
        return new TrafficProfileExport
        {
            Format = format,
            Content = content,
            ConnectionCount = snapshot.Connections.Count,
            EventCount = snapshot.Events.Count,
            Redacted = true,
            NoPayloadGuarantee = NoPayloadGuarantee,
        };
    }

    public static TrafficProfileBundle BuildBundle(ServiceState state, SupportBundleRequest request, DateTime now)
    {
        var profileRequest = new TrafficProfileRequest
        {
            Since = request.Since,
            Until = request.Until,
            Process = request.Process,
            Action = request.Action,
            Protocol = request.Protocol,
            Limit = request.Limit,
        };
        var snapshot = BuildSnapshot(state, profileRequest, now);
        var manifest = JsonSerializer.Serialize(new
        {
            schema = "hostsguard.traffic_profile_manifest.v1",
            generated = now.ToString("o", CultureInfo.InvariantCulture),
            redacted = true,
            no_payload_guarantee = NoPayloadGuarantee,
            filters = snapshot.Filters,
            connection_count = snapshot.Connections.Count,
            event_count = snapshot.Events.Count,
            files = new[] { "traffic_profile.json", "traffic_profile.csv" },
        }, JsonOptions);

        return new TrafficProfileBundle(
            BuildJson(snapshot),
            BuildCsv(snapshot),
            manifest,
            snapshot.Connections.Count,
            snapshot.Events.Count);
    }

    private static TrafficProfileSnapshot BuildSnapshot(ServiceState state, TrafficProfileRequest request, DateTime now)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(request);
        var limit = Math.Clamp(request.Limit > 0 ? request.Limit : 2000, 1, 10_000);
        var eventLimit = Math.Clamp(limit, 1, 2000);
        var filters = new TrafficProfileFilters(
            Clean(request.Since),
            Clean(request.Until),
            Clean(request.Process),
            Clean(request.Action),
            NormalizeProtocol(Clean(request.Protocol)),
            limit);

        var connections = state.Db.GetConnectionHistoryPage(new ConnectionHistoryFilter(
                Limit: limit,
                Search: null,
                Since: filters.Since,
                Until: filters.Until,
                Process: filters.Process,
                Host: null,
                RemoteAddr: null,
                FwStatus: null,
                Protocol: filters.Protocol,
                Offset: 0))
            .Rows
            .Select(RedactConnection)
            .ToList();

        var events = state.Db.GetEvents(new EventLogFilter(
                Limit: eventLimit,
                Offset: 0,
                Search: null,
                Since: filters.Since,
                Until: filters.Until,
                Action: filters.Action,
                Reason: null,
                Domain: null,
                Process: filters.Process,
                Category: null))
            .Rows
            .Select(RedactEvent)
            .ToList();

        return new TrafficProfileSnapshot(
            now.ToString("o", CultureInfo.InvariantCulture),
            filters,
            connections,
            events);
    }

    private static RedactedConnection RedactConnection(ConnHistoryRow row)
        => new(
            row.Ts,
            Redaction.RedactScalar("program", row.Process),
            (int)row.Pid,
            NormalizeProtocol(row.Protocol),
            RedactRemote(row.RemoteAddr),
            (int)row.RemotePort,
            Redaction.RedactText(row.Country),
            Redaction.RedactText(row.FwStatus),
            Redaction.RedactScalar("domain", row.Host),
            BuildWiresharkFilter(row.Protocol, (int)row.RemotePort));

    private static RedactedEvent RedactEvent(EventLogRow row)
        => new(
            row.Id,
            row.Ts,
            row.Category,
            row.Action,
            row.Reason,
            RedactProfileText(row.Domain),
            Redaction.RedactScalar("program", row.Process),
            RedactProfileText(row.Details));

    private static string BuildJson(TrafficProfileSnapshot snapshot)
    {
        var protocolSummary = snapshot.Connections
            .GroupBy(c => c.Protocol.Length == 0 ? "unknown" : c.Protocol, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new { protocol = g.Key, count = g.Count() })
            .ToList();

        var portSummary = snapshot.Connections
            .Where(c => c.RemotePort > 0)
            .GroupBy(c => new { c.Protocol, c.RemotePort })
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key.Protocol, StringComparer.OrdinalIgnoreCase)
            .ThenBy(g => g.Key.RemotePort)
            .Take(30)
            .Select(g => new
            {
                protocol = g.Key.Protocol,
                port = g.Key.RemotePort,
                count = g.Count(),
                wireshark_display_filter = BuildWiresharkFilter(g.Key.Protocol, g.Key.RemotePort),
            })
            .ToList();

        var displayFilters = snapshot.Connections
            .Select(c => c.WiresharkDisplayFilter)
            .Where(f => f.Length != 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(50)
            .ToList();

        return JsonSerializer.Serialize(new
        {
            schema = "hostsguard.traffic_profile.v1",
            generated = snapshot.Generated,
            redacted = true,
            no_payload_guarantee = NoPayloadGuarantee,
            filters = snapshot.Filters,
            wireshark = new
            {
                note = "Use these display-filter hints against an operator-owned packet capture. This file is metadata only.",
                display_filters = displayFilters,
            },
            connection_count = snapshot.Connections.Count,
            event_count = snapshot.Events.Count,
            protocols = protocolSummary,
            ports = portSummary,
            connections = snapshot.Connections.Select(c => new
            {
                ts = c.Ts,
                process = c.Process,
                pid = c.Pid,
                protocol = c.Protocol,
                host = c.Host,
                remote = c.Remote,
                port = c.RemotePort,
                country = c.Country,
                firewall = c.Firewall,
                wireshark_display_filter = c.WiresharkDisplayFilter,
            }),
            events = snapshot.Events.Select(e => new
            {
                id = e.Id,
                ts = e.Ts,
                category = e.Category,
                action = e.Action,
                reason = e.Reason,
                domain = e.Domain,
                process = e.Process,
                details = e.Details,
            }),
        }, JsonOptions);
    }

    private static string BuildCsv(TrafficProfileSnapshot snapshot)
    {
        var sb = new StringBuilder();
        AppendCsvRow(sb, "Kind", "When", "Protocol", "Process", "PID", "Host", "Remote", "Port",
            "Country", "Firewall", "Action", "Reason", "Category", "Details", "WiresharkFilter");
        foreach (var c in snapshot.Connections)
        {
            AppendCsvRow(sb,
                "connection",
                c.Ts,
                c.Protocol,
                c.Process,
                c.Pid.ToString(CultureInfo.InvariantCulture),
                c.Host,
                c.Remote,
                c.RemotePort.ToString(CultureInfo.InvariantCulture),
                c.Country,
                c.Firewall,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                c.WiresharkDisplayFilter);
        }

        foreach (var e in snapshot.Events)
        {
            AppendCsvRow(sb,
                "event",
                e.Ts,
                string.Empty,
                e.Process,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                e.Action,
                e.Reason,
                e.Category,
                e.Details,
                string.Empty);
        }

        return sb.ToString();
    }

    private static string BuildWiresharkFilter(string? protocol, int port)
    {
        var proto = NormalizeProtocol(protocol).ToLowerInvariant();
        if (proto is "tcp" or "udp")
        {
            return port > 0 ? $"{proto}.port == {port}" : proto;
        }

        return port > 0 ? $"tcp.port == {port} || udp.port == {port}" : "ip";
    }

    private static string RedactRemote(string? value)
    {
        var text = (value ?? string.Empty).Trim();
        if (text.Length == 0)
        {
            return string.Empty;
        }

        return IPAddress.TryParse(text, out _)
            ? Redaction.Marker("ip", text)
            : Redaction.RedactText(text);
    }

    private static string RedactProfileText(string? value)
        => AnyIpv4Regex.Replace(Redaction.RedactText(value), m => Redaction.Marker("ip", m.Value));

    private static string NormalizeProtocol(string? protocol)
    {
        var clean = (protocol ?? string.Empty).Trim();
        if (clean.Length == 0)
        {
            return string.Empty;
        }

        return clean.Equals("tcp", StringComparison.OrdinalIgnoreCase) ? "TCP" :
            clean.Equals("udp", StringComparison.OrdinalIgnoreCase) ? "UDP" :
            clean.ToUpperInvariant();
    }

    private static string NormalizeFormat(string? format)
    {
        var clean = (format ?? string.Empty).Trim().ToLowerInvariant();
        return clean is "csv" ? "csv" : "json";
    }

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string Csv(string? value)
    {
        value ??= string.Empty;
        return value.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value;
    }

    private static void AppendCsvRow(StringBuilder sb, params string?[] columns)
    {
        for (var i = 0; i < columns.Length; i++)
        {
            if (i != 0)
            {
                sb.Append(',');
            }

            sb.Append(Csv(columns[i]));
        }

        sb.Append("\r\n");
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly Regex AnyIpv4Regex = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);

    public sealed record TrafficProfileBundle(
        string Json,
        string Csv,
        string Manifest,
        int ConnectionCount,
        int EventCount);

    private sealed record TrafficProfileSnapshot(
        string Generated,
        TrafficProfileFilters Filters,
        IReadOnlyList<RedactedConnection> Connections,
        IReadOnlyList<RedactedEvent> Events);

    private sealed record TrafficProfileFilters(
        string? Since,
        string? Until,
        string? Process,
        string? Action,
        string? Protocol,
        int Limit);

    private sealed record RedactedConnection(
        string Ts,
        string Process,
        int Pid,
        string Protocol,
        string Remote,
        int RemotePort,
        string Country,
        string Firewall,
        string Host,
        string WiresharkDisplayFilter);

    private sealed record RedactedEvent(
        long Id,
        string Ts,
        string Category,
        string Action,
        string Reason,
        string Domain,
        string Process,
        string Details);
}
