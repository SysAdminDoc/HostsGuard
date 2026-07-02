using System.Collections;

namespace HostsGuard.Core;

/// <summary>A firewall rule as HostsGuard models it (COM/PowerShell-agnostic).</summary>
public sealed record FwRule(
    string Name,
    string Direction, // "In" | "Out"
    string Action,    // "Block" | "Allow"
    bool Enabled,
    string RemoteAddr,
    string Protocol,
    string Program,
    string Source,    // "hostsguard" | "system"
    string RemotePorts = "Any");

/// <summary>
/// Shape-tolerant mapping of raw firewall-rule scalar values into <see cref="FwRule"/>.
/// Replaces the Python <c>_parse_fw_rules</c>: tolerant of int/string/bool/list/missing
/// inputs so both the COM engine and any legacy import path produce identical records.
/// Direction/action follow the Windows Firewall COM semantics (Direction 1=In,2=Out;
/// Action 0=Block,1=Allow).
/// </summary>
public static class FwRuleMapper
{
    public const string HostsGuardPrefix = "HG_";

    public static FwRule FromValues(
        string? name,
        object? direction,
        object? action,
        object? enabled,
        object? remoteAddresses,
        object? protocol,
        string? program,
        object? remotePorts = null)
    {
        var n = name ?? string.Empty;
        return new FwRule(
            Name: n,
            Direction: MapDirection(direction),
            Action: MapAction(action),
            Enabled: MapBool(enabled),
            RemoteAddr: MapRemote(remoteAddresses),
            Protocol: MapProtocol(protocol),
            Program: program ?? string.Empty,
            Source: n.StartsWith(HostsGuardPrefix, StringComparison.Ordinal) ? "hostsguard" : "system",
            RemotePorts: MapPorts(remotePorts));
    }

    public static string MapPorts(object? v)
    {
        var s = (v?.ToString() ?? string.Empty).Trim();
        return s is "" or "*" or "Any" or "any" ? "Any" : s;
    }

    public static string MapDirection(object? v)
    {
        var s = (v?.ToString() ?? string.Empty).Trim();
        return s switch
        {
            "1" or "In" or "in" or "Inbound" or "inbound" => "In",
            "2" or "Out" or "out" or "Outbound" or "outbound" => "Out",
            _ => "Out",
        };
    }

    public static string MapAction(object? v)
    {
        var s = (v?.ToString() ?? string.Empty).Trim();
        // COM: Block=0, Allow=1.
        return s switch
        {
            "0" or "Block" or "block" => "Block",
            "1" or "Allow" or "allow" => "Allow",
            _ => "Block",
        };
    }

    public static bool MapBool(object? v)
    {
        switch (v)
        {
            case null:
                return false;
            case bool b:
                return b;
            case int i:
                return i != 0;
        }

        var s = v.ToString()?.Trim();
        return s is "1" or "True" or "true" or "Enabled" or "enabled";
    }

    public static string MapRemote(object? v)
    {
        string joined;
        if (v is string s)
        {
            joined = s;
        }
        else if (v is IEnumerable en and not string)
        {
            joined = string.Join(',', en.Cast<object?>().Select(x => x?.ToString() ?? string.Empty).Where(x => x.Length != 0));
        }
        else
        {
            joined = v?.ToString() ?? string.Empty;
        }

        joined = joined.Trim();
        return joined is "" or "*" or "Any" ? "Any" : joined;
    }

    public static string MapProtocol(object? v)
    {
        var s = (v?.ToString() ?? string.Empty).Trim();
        return s switch
        {
            "6" or "TCP" or "tcp" => "TCP",
            "17" or "UDP" or "udp" => "UDP",
            "1" or "ICMPv4" => "ICMPv4",
            "58" or "ICMPv6" => "ICMPv6",
            "" or "256" or "Any" or "any" => "Any",
            _ => s,
        };
    }
}
