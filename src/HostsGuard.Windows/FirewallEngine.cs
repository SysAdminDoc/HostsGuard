using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Net.NetworkInformation;
using Microsoft.CSharp.RuntimeBinder;
using HostsGuard.Core;

namespace HostsGuard.Windows;

/// <summary>
/// Persistent Windows Firewall rule engine via the <c>HNetCfg.FwPolicy2</c> COM
/// object (INetFwPolicy2) — replaces PowerShell New-NetFirewallRule shelling.
/// Late-bound COM keeps the build free of an interop assembly; mutation requires
/// elevation and is exercised by the admin-gated round-trip test.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FirewallEngine : IFirewallEngine
{
    // NET_FW_RULE_DIRECTION_
    private const int DirIn = 1;
    private const int DirOut = 2;

    // NET_FW_ACTION_
    private const int ActionBlock = 0;
    private const int ActionAllow = 1;

    // NET_FW_IP_PROTOCOL_
    private const int ProtoTcp = 6;
    private const int ProtoUdp = 17;
    private const int ProtoAny = 256;

    // NET_FW_PROFILE2_ALL
    private const int ProfileAll = 0x7FFFFFFF;

    private static dynamic CreatePolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new InvalidOperationException("Windows Firewall COM (HNetCfg.FwPolicy2) is unavailable.");
        return Activator.CreateInstance(type)
            ?? throw new InvalidOperationException("Failed to create the firewall policy COM object.");
    }

    /// <summary>Enumerate all rules, mapped into <see cref="FwRule"/> records.</summary>
    public IReadOnlyList<FwRule> ListRules()
    {
        var policy = CreatePolicy();
        var rules = new List<FwRule>();
        var packages = ListPackages()
            .ToDictionary(p => p.PackageSid, StringComparer.OrdinalIgnoreCase);
        foreach (var comRule in policy.Rules)
        {
            try
            {
                string packageSid = SafeLocalAppPackageId(comRule);
                packages.TryGetValue(packageSid, out var package);
                rules.Add(FwRuleMapper.FromValues(
                    (string?)comRule.Name,
                    (int)comRule.Direction,
                    (int)comRule.Action,
                    (bool)comRule.Enabled,
                    (string?)comRule.RemoteAddresses,
                    (int)comRule.Protocol,
                    SafeApplicationName(comRule),
                    SafeRemotePorts(comRule),
                    SafeServiceName(comRule),
                    SafeLocalPorts(comRule),
                    SafeInterfaces(comRule),
                    package?.PackageFamilyName,
                    packageSid,
                    package?.DisplayName,
                    package?.PackageFullName,
                    package?.Binaries,
                    SafeProfiles(comRule),
                    SafeLocalAddresses(comRule)));
            }
            catch (COMException)
            {
                // Skip rules that fail to project (some system rules are partial).
            }
        }

        return rules;
    }

    public IReadOnlyList<FwAppPackage> ListPackages()
    {
        try
        {
            return AppContainerPackages.List();
        }
        catch (Exception ex) when (ex is COMException or System.ComponentModel.Win32Exception or EntryPointNotFoundException or DllNotFoundException)
        {
            return Array.Empty<FwAppPackage>();
        }
    }

    public IReadOnlyList<FwInterfaceAlias> ListInterfaceAliases() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(static adapter => adapter.Name.Length != 0)
        .Select(static adapter => new FwInterfaceAlias(
            adapter.Name,
            adapter.Description,
            adapter.OperationalStatus == OperationalStatus.Up,
            adapter.NetworkInterfaceType.ToString()))
        .DistinctBy(static adapter => adapter.Alias, StringComparer.OrdinalIgnoreCase)
        .OrderByDescending(static adapter => adapter.IsUp)
        .ThenBy(static adapter => adapter.Alias, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    /// <summary>Create a rule. Returns false if a rule with the same name already exists.</summary>
    public bool CreateRule(FwRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var policy = CreatePolicy();
        if (Exists(policy, rule.Name))
        {
            return false;
        }

        var type = Type.GetTypeFromProgID("HNetCfg.FWRule")
            ?? throw new InvalidOperationException("HNetCfg.FWRule COM is unavailable.");
        dynamic com = Activator.CreateInstance(type)!;
        com.Name = rule.Name;
        com.Direction = rule.Direction == "In" ? DirIn : DirOut;
        com.Action = rule.Action == "Allow" ? ActionAllow : ActionBlock;
        com.Enabled = rule.Enabled;
        com.Profiles = ProfileMask(rule.Profiles);
        if (rule.RemoteAddr is not ("" or "Any"))
        {
            com.RemoteAddresses = rule.RemoteAddr;
        }

        if (rule.LocalAddresses is not ("" or "Any"))
        {
            com.LocalAddresses = rule.LocalAddresses;
        }

        com.Protocol = rule.Protocol switch { "TCP" => ProtoTcp, "UDP" => ProtoUdp, _ => ProtoAny };
        // COM requires Protocol set BEFORE ports, and only TCP/UDP accept ports.
        if (rule.LocalPorts is not ("" or "Any") && rule.Protocol is "TCP" or "UDP")
        {
            com.LocalPorts = rule.LocalPorts;
        }

        if (rule.RemotePorts is not ("" or "Any") && rule.Protocol is "TCP" or "UDP")
        {
            com.RemotePorts = rule.RemotePorts;
        }

        if (rule.PackageSid.Length != 0)
        {
            com.LocalAppPackageId = rule.PackageSid;
        }

        if (rule.Program.Length != 0)
        {
            com.ApplicationName = rule.Program;
        }

        if (rule.ServiceName.Length != 0)
        {
            // Scope the rule to one SCM service — blocks Dnscache without
            // blocking every other service hosted by svchost.exe (NET-073).
            com.serviceName = rule.ServiceName;
        }

        if (rule.Interfaces is not ("" or "Any"))
        {
            var interfaces = rule.Interfaces
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (interfaces.Length != 0)
            {
                com.Interfaces = interfaces;
            }
        }

        policy.Rules.Add(com);
        return true;
    }

    public bool ReplaceRule(FwRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var original = ListRules().FirstOrDefault(existing =>
            existing.Name.Equals(rule.Name, StringComparison.Ordinal));
        if (original is null || !DeleteRule(rule.Name))
        {
            return false;
        }

        try
        {
            if (CreateRule(rule))
            {
                return true;
            }
        }
        catch
        {
            _ = CreateRule(original);
            throw;
        }

        _ = CreateRule(original);
        return false;
    }

    /// <summary>Delete a rule by name. Returns false if it did not exist.</summary>
    public bool DeleteRule(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var policy = CreatePolicy();
        if (!Exists(policy, name))
        {
            return false;
        }

        policy.Rules.Remove(name);
        return true;
    }

    /// <summary>Enable/disable a rule by name.</summary>
    public bool SetRuleEnabled(string name, bool enabled)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var policy = CreatePolicy();
        foreach (var comRule in policy.Rules)
        {
            if (string.Equals((string?)comRule.Name, name, StringComparison.Ordinal))
            {
                comRule.Enabled = enabled;
                return true;
            }
        }

        return false;
    }

    public bool RuleExists(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return Exists(CreatePolicy(), name);
    }

    // NET_FW_PROFILE2_ single-profile values for posture control.
    private static readonly (string Name, int Value)[] PostureProfiles =
    {
        ("Domain", 1),
        ("Private", 2),
        ("Public", 4),
    };

    public IReadOnlyList<FwProfilePosture> GetPosture()
    {
        var policy = CreatePolicy();
        var result = new List<FwProfilePosture>(PostureProfiles.Length);
        foreach (var (name, value) in PostureProfiles)
        {
            result.Add(new FwProfilePosture(
                name,
                (bool)policy.FirewallEnabled[value],
                (int)policy.DefaultOutboundAction[value] == ActionBlock));
        }

        return result;
    }

    public IReadOnlyList<InboundFirewallProfile> GetActiveInboundProfiles()
    {
        var policy = CreatePolicy();
        var current = (int)policy.CurrentProfileTypes;
        var result = new List<InboundFirewallProfile>(3);
        foreach (var (name, value) in PostureProfiles)
        {
            if ((current & value) == 0)
            {
                continue;
            }

            result.Add(new InboundFirewallProfile(
                name,
                (bool)policy.FirewallEnabled[value],
                (int)policy.DefaultInboundAction[value] == ActionBlock));
        }

        return result;
    }

    public FirewallLocalPolicyModifyState GetLocalPolicyModifyState()
    {
        var value = (int)CreatePolicy().LocalPolicyModifyState;
        return value switch
        {
            0 => FirewallLocalPolicyModifyState.Ok,
            1 => FirewallLocalPolicyModifyState.GroupPolicyOverride,
            2 => FirewallLocalPolicyModifyState.InboundBlocked,
            _ => FirewallLocalPolicyModifyState.GroupPolicyOverride,
        };
    }

    public void SetDefaultOutboundBlock(bool block)
    {
        var policy = CreatePolicy();
        foreach (var (_, value) in PostureProfiles)
        {
            var isBlock = (int)policy.DefaultOutboundAction[value] == ActionBlock;
            if (isBlock != block)
            {
                policy.DefaultOutboundAction[value] = block ? ActionBlock : ActionAllow;
            }
        }
    }

    public void SetDefaultOutboundBlock(IReadOnlyDictionary<string, bool> perProfile)
    {
        ArgumentNullException.ThrowIfNull(perProfile);
        var policy = CreatePolicy();
        foreach (var (name, value) in PostureProfiles)
        {
            if (!perProfile.TryGetValue(name, out var block))
            {
                continue;
            }

            var isBlock = (int)policy.DefaultOutboundAction[value] == ActionBlock;
            if (isBlock != block)
            {
                policy.DefaultOutboundAction[value] = block ? ActionBlock : ActionAllow;
            }
        }
    }

    public bool SetRuleProgram(string name, string programPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(programPath);
        var policy = CreatePolicy();
        foreach (var comRule in policy.Rules)
        {
            if (string.Equals((string?)comRule.Name, name, StringComparison.Ordinal))
            {
                comRule.ApplicationName = programPath;
                return true;
            }
        }

        return false;
    }

    public bool SetRuleRemoteAddresses(string name, string remoteAddresses)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(remoteAddresses);
        var policy = CreatePolicy();
        foreach (var comRule in policy.Rules)
        {
            if (string.Equals((string?)comRule.Name, name, StringComparison.Ordinal))
            {
                comRule.RemoteAddresses = remoteAddresses is "Any" ? "*" : remoteAddresses;
                return true;
            }
        }

        return false;
    }

    private static bool Exists(dynamic policy, string name)
    {
        foreach (var comRule in policy.Rules)
        {
            if (string.Equals((string?)comRule.Name, name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string SafeRemotePorts(dynamic comRule)
    {
        try
        {
            return (string?)comRule.RemotePorts ?? string.Empty;
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException)
        {
            return string.Empty;
        }
    }

    private static string SafeLocalAddresses(dynamic comRule)
    {
        try
        {
            return (string?)comRule.LocalAddresses ?? string.Empty;
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException)
        {
            return string.Empty;
        }
    }

    private static string SafeLocalPorts(dynamic comRule)
    {
        try
        {
            return (string?)comRule.LocalPorts ?? string.Empty;
        }
        catch (COMException)
        {
            return string.Empty;
        }
    }

    private static string SafeApplicationName(dynamic comRule)
    {
        try
        {
            return (string?)comRule.ApplicationName ?? string.Empty;
        }
        catch (COMException)
        {
            return string.Empty;
        }
    }

    private static string SafeServiceName(dynamic comRule)
    {
        try
        {
            return (string?)comRule.serviceName ?? string.Empty;
        }
        catch (COMException)
        {
            return string.Empty;
        }
    }

    private static string SafeInterfaces(dynamic comRule)
    {
        try
        {
            return FwRuleMapper.MapInterfaces(comRule.Interfaces);
        }
        catch (COMException)
        {
            return "Any";
        }
    }

    private static string SafeLocalAppPackageId(dynamic comRule)
    {
        try
        {
            return (string?)comRule.LocalAppPackageId ?? string.Empty;
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException)
        {
            return string.Empty;
        }
    }

    private static object SafeProfiles(dynamic comRule)
    {
        try
        {
            return (int)comRule.Profiles;
        }
        catch (Exception ex) when (ex is COMException or RuntimeBinderException)
        {
            return ProfileAll;
        }
    }

    private static int ProfileMask(string profiles)
    {
        if (profiles is "" or "Any" or "All" or "*")
        {
            return ProfileAll;
        }

        var mask = 0;
        foreach (var profile in profiles.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            mask |= profile.ToLowerInvariant() switch
            {
                "domain" => 1,
                "private" => 2,
                "public" => 4,
                _ => 0,
            };
        }

        return mask == 0 ? ProfileAll : mask;
    }
}
