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
    string RemotePorts = "Any",
    string ServiceName = "", // SCM short name — scopes the rule to one service (NET-073)
    string LocalPorts = "Any",
    string Interfaces = "Any",
    string PackageFamilyName = "",
    string PackageSid = "",
    string PackageDisplayName = "",
    string PackageFullName = "",
    string PackageBinaries = "",
    string Profiles = "Any",
    string LocalAddresses = "Any",
    string Description = "");

/// <summary>Installed app-container/MSIX package identity for firewall rule authoring.</summary>
public sealed record FwAppPackage(
    string PackageFamilyName,
    string PackageSid,
    string DisplayName,
    string PackageFullName,
    string Binaries);

public sealed record FwInterfaceAlias(string Alias, string Description, bool IsUp, string InterfaceType);

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
        object? remotePorts = null,
        string? serviceName = null,
        object? localPorts = null,
        object? interfaces = null,
        string? packageFamilyName = null,
        string? packageSid = null,
        string? packageDisplayName = null,
        string? packageFullName = null,
        object? packageBinaries = null,
        object? profiles = null,
        object? localAddresses = null,
        string? description = null)
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
            RemotePorts: MapPorts(remotePorts),
            ServiceName: MapService(serviceName),
            LocalPorts: MapPorts(localPorts),
            Interfaces: MapInterfaces(interfaces),
            PackageFamilyName: MapPackage(packageFamilyName),
            PackageSid: MapPackage(packageSid),
            PackageDisplayName: MapPackage(packageDisplayName),
            PackageFullName: MapPackage(packageFullName),
            PackageBinaries: MapPackageList(packageBinaries),
            Profiles: MapProfiles(profiles),
            LocalAddresses: MapRemote(localAddresses),
            Description: MapDescription(description));
    }

    /// <summary>Normalize the COM serviceName value ("*" means any/none for our model).</summary>
    public static string MapService(string? v)
    {
        var s = (v ?? string.Empty).Trim();
        return s is "*" ? string.Empty : s;
    }

    public static string MapPorts(object? v)
    {
        var s = (v?.ToString() ?? string.Empty).Trim();
        return s is "" or "*" or "Any" or "any" ? "Any" : s;
    }

    public static string MapInterfaces(object? v)
    {
        string joined;
        if (v is string s)
        {
            joined = s;
        }
        else if (v is IEnumerable en and not string)
        {
            joined = string.Join(',', en.Cast<object?>()
                .Select(x => x?.ToString()?.Trim() ?? string.Empty)
                .Where(x => x.Length != 0)
                .Distinct(StringComparer.OrdinalIgnoreCase));
        }
        else
        {
            joined = v?.ToString() ?? string.Empty;
        }

        joined = joined.Trim();
        return joined is "" or "*" or "Any" or "any" ? "Any" : joined;
    }

    /// <summary>Normalize NET_FW_PROFILE2 flags or profile names into a stable list.</summary>
    public static string MapProfiles(object? value)
    {
        if (value is null)
        {
            return "Any";
        }

        if (value is IEnumerable values and not string)
        {
            return MapProfiles(string.Join(',', values.Cast<object?>()
                .Select(static item => item?.ToString()?.Trim() ?? string.Empty)
                .Where(static item => item.Length != 0)));
        }

        if (int.TryParse(value.ToString(), out var mask))
        {
            if (mask is -1 or 0x7FFFFFFF || (mask & ~7) != 0)
            {
                return "Any";
            }

            var names = new List<string>(3);
            if ((mask & 1) != 0) names.Add("Domain");
            if ((mask & 2) != 0) names.Add("Private");
            if ((mask & 4) != 0) names.Add("Public");
            return names.Count == 0 ? "Any" : string.Join(',', names);
        }

        var mapped = value.ToString()!
            .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static name => name.ToLowerInvariant() switch
            {
                "domain" => "Domain",
                "private" => "Private",
                "public" => "Public",
                _ => name,
            })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return mapped.Length == 0 || mapped.Any(static name => name is "*" or "Any" or "All")
            ? "Any"
            : string.Join(',', mapped);
    }

    public static string MapPackage(string? v)
        => (v ?? string.Empty).Trim();

    public static string MapDescription(string? value) => (value ?? string.Empty).Trim();

    public static string MapPackageList(object? v)
    {
        if (v is null)
        {
            return string.Empty;
        }

        if (v is string s)
        {
            return s.Trim();
        }

        if (v is IEnumerable en and not string)
        {
            return string.Join(';', en.Cast<object?>()
                .Select(x => x?.ToString()?.Trim() ?? string.Empty)
                .Where(x => x.Length != 0)
                .Distinct(StringComparer.OrdinalIgnoreCase));
        }

        return v.ToString()?.Trim() ?? string.Empty;
    }

    public static string RuleToken(string value)
    {
        var token = new string((value ?? string.Empty)
            .Select(ch => char.IsLetterOrDigit(ch) ? ch : '_')
            .ToArray())
            .Trim('_');
        while (token.Contains("__", StringComparison.Ordinal))
        {
            token = token.Replace("__", "_", StringComparison.Ordinal);
        }

        return token.Length == 0 ? "package" : token;
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
