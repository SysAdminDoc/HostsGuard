using System.Net;
using System.Net.Sockets;

namespace HostsGuard.Core;

/// <summary>A transport listener observed locally. This is not proof of external reachability.</summary>
public sealed record ListenerEndpoint(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    int Pid,
    string ProcessName);

/// <summary>Best-effort identity joined to a listener's owning PID.</summary>
public sealed record ListenerOwnerAttribution(
    int Pid,
    string ProcessPath = "",
    string ServiceName = "",
    string ServiceDisplayName = "",
    string PackageFamilyName = "",
    string PackageSid = "");

/// <summary>Current inbound posture for one active Windows Firewall profile.</summary>
public sealed record InboundFirewallProfile(
    string Name,
    bool FirewallEnabled,
    bool DefaultInboundBlock);

public enum ListenerBindScope
{
    Unknown,
    Any,
    Loopback,
    LinkLocal,
    Private,
    Public,
}

public enum ListenerInboundAction
{
    BlockRule,
    AllowRule,
    DefaultBlock,
    DefaultAllow,
    FirewallDisabled,
    ProfileMismatch,
    RestrictedAllow,
    RestrictedBlock,
    RestrictedMixed,
}

public sealed record ListenerProfileExposure(
    string Profile,
    ListenerInboundAction Action,
    IReadOnlyList<string> RuleNames,
    bool DefaultInboundBlock = true);

/// <summary>
/// Local effective-policy assessment. <see cref="PublicBound"/> means the socket is
/// bound to a wildcard or globally routable local address; it never asserts that a
/// remote host can cross NAT, upstream firewalls, IPsec, or other network controls.
/// </summary>
public sealed record ListenerExposureAssessment(
    ListenerEndpoint Endpoint,
    ListenerOwnerAttribution Owner,
    ListenerBindScope BindScope,
    bool PublicBound,
    bool NeedsAttention,
    string Finding,
    IReadOnlyList<ListenerProfileExposure> Profiles);

/// <summary>Pure, deterministic listener-to-owner-to-firewall policy analyzer.</summary>
public static class ListenerExposureAnalyzer
{
    public static IReadOnlyList<ListenerExposureAssessment> Analyze(
        IEnumerable<ListenerEndpoint> listeners,
        IEnumerable<ListenerOwnerAttribution> owners,
        IEnumerable<FwRule> rules,
        IEnumerable<InboundFirewallProfile> activeProfiles)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        ArgumentNullException.ThrowIfNull(owners);
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(activeProfiles);

        var ownerByPid = owners
            .GroupBy(static owner => owner.Pid)
            .ToDictionary(static group => group.Key, static group => group.First());
        var inboundRules = rules
            .Where(static rule => rule.Enabled && rule.Direction.Equals("In", StringComparison.OrdinalIgnoreCase))
            .OrderBy(static rule => rule.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var profiles = activeProfiles
            .GroupBy(static profile => profile.Name, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .OrderBy(static profile => ProfileOrder(profile.Name))
            .ThenBy(static profile => profile.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return listeners
            .Where(IsListener)
            .Select(Normalize)
            .GroupBy(static listener => (listener.Protocol, listener.LocalAddress, listener.LocalPort, listener.Pid))
            .Select(static group => group.First())
            .Select(listener => AnalyzeOne(
                listener,
                ownerByPid.GetValueOrDefault(listener.Pid) ?? new ListenerOwnerAttribution(listener.Pid),
                inboundRules,
                profiles))
            .OrderBy(static row => ProtocolOrder(row.Endpoint.Protocol))
            .ThenBy(static row => AddressFamilyOrder(row.Endpoint.LocalAddress))
            .ThenBy(static row => row.Endpoint.LocalAddress, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static row => row.Endpoint.LocalPort)
            .ThenBy(static row => row.Endpoint.Pid)
            .ToArray();
    }

    private static ListenerExposureAssessment AnalyzeOne(
        ListenerEndpoint endpoint,
        ListenerOwnerAttribution owner,
        IReadOnlyList<FwRule> inboundRules,
        IReadOnlyList<InboundFirewallProfile> profiles)
    {
        var scope = ClassifyBind(endpoint.LocalAddress);
        var publicBound = scope is ListenerBindScope.Any or ListenerBindScope.Public;
        var candidates = inboundRules.Where(rule => RuleTargets(rule, endpoint, owner)).ToArray();
        var profileResults = profiles.Select(profile => AnalyzeProfile(endpoint, profile, candidates)).ToArray();
        var profileUnknown = profiles.Count == 0;
        var profileMismatch = candidates.Length != 0 && profileResults.Length != 0 &&
            profileResults.All(static result => result.Action == ListenerInboundAction.ProfileMismatch);
        var unruled = candidates.Length == 0;
        var needsAttention = publicBound && (profileUnknown || unruled || profileMismatch ||
            profileResults.Select((result, index) => (result, index)).Any(pair =>
                pair.result.Action is ListenerInboundAction.AllowRule or ListenerInboundAction.DefaultAllow or
                    ListenerInboundAction.FirewallDisabled or ListenerInboundAction.RestrictedAllow or ListenerInboundAction.RestrictedMixed ||
                (pair.result.Action == ListenerInboundAction.RestrictedBlock && !profiles[pair.index].DefaultInboundBlock)));

        var finding = !publicBound ? "local_bind"
            : profileUnknown ? "public_bound_profile_unknown"
            : profileMismatch ? "public_bound_profile_mismatch"
            : unruled ? "public_bound_unruled"
            : profileResults.Any(static result => result.Action == ListenerInboundAction.FirewallDisabled) ? "public_bound_firewall_disabled"
            : profileResults.Any(static result => result.Action is ListenerInboundAction.AllowRule or ListenerInboundAction.DefaultAllow or
                ListenerInboundAction.RestrictedAllow or ListenerInboundAction.RestrictedMixed) ||
              profileResults.Select((result, index) => (result, index)).Any(pair =>
                  pair.result.Action == ListenerInboundAction.RestrictedBlock && !profiles[pair.index].DefaultInboundBlock)
                ? "public_bound_permitted_locally"
            : "public_bound_blocked_locally";

        return new ListenerExposureAssessment(endpoint, owner, scope, publicBound, needsAttention, finding, profileResults);
    }

    private static ListenerProfileExposure AnalyzeProfile(
        ListenerEndpoint endpoint,
        InboundFirewallProfile profile,
        IReadOnlyList<FwRule> candidates)
    {
        var profileRules = candidates.Where(rule => AppliesToProfile(rule.Profiles, profile.Name)).ToArray();
        if (!profile.FirewallEnabled)
        {
            return new(profile.Name, ListenerInboundAction.FirewallDisabled, Names(profileRules), profile.DefaultInboundBlock);
        }

        var blanket = profileRules.Where(rule => IsBlanketRule(rule, endpoint)).ToArray();
        var block = blanket.Where(static rule => rule.Action.Equals("Block", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (block.Length != 0)
        {
            return new(profile.Name, ListenerInboundAction.BlockRule, Names(block), profile.DefaultInboundBlock);
        }

        var allow = blanket.Where(static rule => rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (allow.Length != 0)
        {
            return new(profile.Name, ListenerInboundAction.AllowRule, Names(allow), profile.DefaultInboundBlock);
        }

        var restricted = profileRules.Except(blanket).ToArray();
        var restrictedAllow = restricted.Any(static rule => rule.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase));
        var restrictedBlock = restricted.Any(static rule => rule.Action.Equals("Block", StringComparison.OrdinalIgnoreCase));
        if (restrictedAllow || restrictedBlock)
        {
            var action = restrictedAllow && restrictedBlock ? ListenerInboundAction.RestrictedMixed
                : restrictedAllow ? ListenerInboundAction.RestrictedAllow
                : ListenerInboundAction.RestrictedBlock;
            return new(profile.Name, action, Names(restricted), profile.DefaultInboundBlock);
        }

        if (candidates.Count != 0)
        {
            return new(profile.Name, ListenerInboundAction.ProfileMismatch, Array.Empty<string>(), profile.DefaultInboundBlock);
        }

        return new(profile.Name,
            profile.DefaultInboundBlock ? ListenerInboundAction.DefaultBlock : ListenerInboundAction.DefaultAllow,
            Array.Empty<string>(),
            profile.DefaultInboundBlock);
    }

    private static IReadOnlyList<string> Names(IEnumerable<FwRule> rules) => rules
        .Select(static rule => rule.Name)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Order(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static bool IsListener(ListenerEndpoint listener) =>
        listener.LocalPort is >= 1 and <= 65535 &&
        (listener.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) ||
         listener.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase));

    private static ListenerEndpoint Normalize(ListenerEndpoint listener) => listener with
    {
        Protocol = listener.Protocol.ToUpperInvariant(),
        LocalAddress = NormalizeAddress(listener.LocalAddress),
        ProcessName = listener.ProcessName.Trim(),
    };

    private static string NormalizeAddress(string value) =>
        IPAddress.TryParse(value.Split('%')[0], out var address) ? address.ToString() : value.Trim();

    private static bool RuleTargets(FwRule rule, ListenerEndpoint listener, ListenerOwnerAttribution owner)
    {
        if (!rule.Protocol.Equals("Any", StringComparison.OrdinalIgnoreCase) &&
            !rule.Protocol.Equals(listener.Protocol, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!PortMatches(rule.LocalPorts, listener.LocalPort))
        {
            return false;
        }

        if (LocalAddressMatch(rule.LocalAddresses, listener.LocalAddress) == AddressMatch.None)
        {
            return false;
        }

        if (rule.Program.Length != 0 && !PathEquals(rule.Program, owner.ProcessPath))
        {
            return false;
        }

        if (rule.ServiceName.Length != 0 && !rule.ServiceName.Equals(owner.ServiceName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (rule.PackageFamilyName.Length != 0 && !rule.PackageFamilyName.Equals(owner.PackageFamilyName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (rule.PackageSid.Length == 0)
        {
            return true;
        }

        if (owner.PackageSid.Length != 0)
        {
            return rule.PackageSid.Equals(owner.PackageSid, StringComparison.OrdinalIgnoreCase);
        }

        // NetworkIsolation rules commonly project both PFN and SID, while PID
        // attribution may only recover the PFN. An exact family match is enough.
        return rule.PackageFamilyName.Length != 0 && owner.PackageFamilyName.Length != 0;
    }

    private static bool IsBlanketRule(FwRule rule, ListenerEndpoint endpoint) =>
        IsAny(rule.RemoteAddr) && IsAny(rule.RemotePorts) && IsAny(rule.Interfaces) &&
        LocalAddressMatch(rule.LocalAddresses, endpoint.LocalAddress) == AddressMatch.Complete;

    private static bool IsAny(string value) => value is "" or "Any" or "*";

    private enum AddressMatch { None, Scoped, Complete }

    private static AddressMatch LocalAddressMatch(string specification, string localAddress)
    {
        if (IsAny(specification)) return AddressMatch.Complete;
        if (!IPAddress.TryParse(localAddress.Split('%')[0], out var listener)) return AddressMatch.Scoped;
        var wildcard = listener.Equals(IPAddress.Any) || listener.Equals(IPAddress.IPv6Any);
        var unknown = false;
        foreach (var token in specification.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (IPAddress.TryParse(token.Split('%')[0], out var exact))
            {
                if (wildcard || exact.Equals(listener)) return wildcard ? AddressMatch.Scoped : AddressMatch.Complete;
                continue;
            }

            var range = token.Split('-', 2, StringSplitOptions.TrimEntries);
            if (range.Length == 2 && IPAddress.TryParse(range[0], out var first) && IPAddress.TryParse(range[1], out var last))
            {
                if (wildcard || IsInRange(listener, first, last)) return wildcard ? AddressMatch.Scoped : AddressMatch.Complete;
                continue;
            }

            var cidr = token.Split('/', 2, StringSplitOptions.TrimEntries);
            if (cidr.Length == 2 && IPAddress.TryParse(cidr[0], out var network) && int.TryParse(cidr[1], out var bits))
            {
                if (wildcard || IsInCidr(listener, network, bits)) return wildcard ? AddressMatch.Scoped : AddressMatch.Complete;
                continue;
            }

            // Windows special keywords (LocalSubnet, DNS, DHCP, WINS,
            // DefaultGateway) require interface state not present in this pure model.
            unknown = true;
        }

        return unknown ? AddressMatch.Scoped : AddressMatch.None;
    }

    private static bool IsInRange(IPAddress value, IPAddress first, IPAddress last)
    {
        var address = value.GetAddressBytes();
        var low = first.GetAddressBytes();
        var high = last.GetAddressBytes();
        return address.Length == low.Length && address.Length == high.Length &&
            CompareBytes(address, low) >= 0 && CompareBytes(address, high) <= 0;
    }

    private static bool IsInCidr(IPAddress value, IPAddress network, int bits)
    {
        var address = value.GetAddressBytes();
        var prefix = network.GetAddressBytes();
        if (address.Length != prefix.Length || bits < 0 || bits > address.Length * 8) return false;
        var fullBytes = bits / 8;
        var remaining = bits % 8;
        if (!address.AsSpan(0, fullBytes).SequenceEqual(prefix.AsSpan(0, fullBytes))) return false;
        if (remaining == 0) return true;
        var mask = (byte)(0xFF << (8 - remaining));
        return (address[fullBytes] & mask) == (prefix[fullBytes] & mask);
    }

    private static int CompareBytes(byte[] left, byte[] right)
    {
        for (var index = 0; index < left.Length; index++)
        {
            var compared = left[index].CompareTo(right[index]);
            if (compared != 0) return compared;
        }

        return 0;
    }

    private static bool PathEquals(string left, string right)
    {
        if (right.Length == 0) return false;
        try
        {
            return Path.GetFullPath(Environment.ExpandEnvironmentVariables(left))
                .Equals(Path.GetFullPath(Environment.ExpandEnvironmentVariables(right)), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return left.Equals(right, StringComparison.OrdinalIgnoreCase);
        }
    }

    internal static bool PortMatches(string specification, int port)
    {
        if (specification is "" or "Any" or "*") return true;
        foreach (var token in specification.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(token, out var exact) && exact == port) return true;
            var bounds = token.Split('-', 2, StringSplitOptions.TrimEntries);
            if (bounds.Length == 2 && int.TryParse(bounds[0], out var first) &&
                int.TryParse(bounds[1], out var last) && port >= first && port <= last)
            {
                return true;
            }
        }

        return false;
    }

    internal static bool AppliesToProfile(string specification, string profile) =>
        specification is "" or "Any" or "All" or "*" || specification
            .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(profile, StringComparer.OrdinalIgnoreCase);

    internal static ListenerBindScope ClassifyBind(string value)
    {
        var raw = value.Split('%')[0];
        if (!IPAddress.TryParse(raw, out var address)) return ListenerBindScope.Unknown;
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return ListenerBindScope.Any;
        if (address.IsIPv4MappedToIPv6) return ClassifyBind(address.MapToIPv4().ToString());
        if (IPAddress.IsLoopback(address)) return ListenerBindScope.Loopback;
        if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || IsIpv4(address, 169, 254)) return ListenerBindScope.LinkLocal;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 10 || bytes[0] == 127 ||
                (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                (bytes[0] == 192 && bytes[1] == 168) ||
                (bytes[0] == 100 && bytes[1] is >= 64 and <= 127) ||
                (bytes[0] == 192 && bytes[1] == 0 && bytes[2] is 0 or 2) ||
                (bytes[0] == 198 && bytes[1] is 18 or 19) ||
                (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) ||
                (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) ||
                bytes[0] == 0 || bytes[0] >= 224)
            {
                return ListenerBindScope.Private;
            }
        }
        else
        {
            var bytes = address.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC || address.IsIPv6SiteLocal || address.IsIPv6Multicast ||
                (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8))
            {
                return ListenerBindScope.Private;
            }
        }

        return ListenerBindScope.Public;
    }

    private static bool IsIpv4(IPAddress address, byte first, byte second)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var bytes = address.GetAddressBytes();
        return bytes[0] == first && bytes[1] == second;
    }

    private static int ProtocolOrder(string protocol) => protocol == "TCP" ? 0 : 1;
    private static int AddressFamilyOrder(string address) =>
        IPAddress.TryParse(address, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetwork ? 0 : 1;
    private static int ProfileOrder(string profile) => profile.ToLowerInvariant() switch
    {
        "domain" => 0,
        "private" => 1,
        "public" => 2,
        _ => 3,
    };
}
