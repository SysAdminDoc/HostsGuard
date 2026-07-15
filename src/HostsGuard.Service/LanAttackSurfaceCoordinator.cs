using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

public sealed record LanAttackSurfaceToggleState(
    string Key,
    string Label,
    bool Blocked,
    string Status,
    string BreakNote);

/// <summary>One-click reversible LAN discovery/file-sharing hardening controls.</summary>
public sealed class LanAttackSurfaceCoordinator
{
    private const string MetaPrefix = "lan_surface:";
    private readonly HostsDatabase _db;
    private readonly IFirewallEngine? _firewall;
    private readonly ILanAttackSurfaceStore _store;

    public LanAttackSurfaceCoordinator(HostsDatabase db, IFirewallEngine? firewall, ILanAttackSurfaceStore store)
    {
        _db = db;
        _firewall = firewall;
        _store = store;
    }

    public IReadOnlyList<LanAttackSurfaceToggleState> List()
        => Definitions.Select(StateFor).ToList();

    public Ack Set(string key, bool blocked)
    {
        var definition = Definitions.FirstOrDefault(d => string.Equals(d.Key, key, StringComparison.Ordinal));
        if (definition is null)
        {
            return Error("invalid_lan_surface", "unknown LAN attack-surface toggle");
        }

        try
        {
            _store.SetBlocked(definition.Key, blocked);
            if (_firewall is { } fw)
            {
                foreach (var rule in definition.Rules)
                {
                    fw.DeleteRule(rule.Name);
                    _db.RemoveFwState(rule.Name);
                    if (blocked)
                    {
                        var created = fw.CreateRule(rule.ToFwRule());
                        if (created || fw.RuleExists(rule.Name))
                        {
                            _db.UpsertFwState(
                                rule.Name,
                                rule.Direction,
                                "Block",
                                rule.RemoteAddr,
                                rule.Protocol,
                                rule.Program,
                                rule.RemotePorts,
                                rule.LocalPorts,
                                rule.ServiceName);
                        }
                    }
                }
            }

            _db.SetMeta(MetaPrefix + definition.Key, blocked ? "blocked" : "off");
            _db.LogEvent(definition.Key, blocked ? "lan_surface_blocked" : "lan_surface_unblocked",
                details: definition.Label, reason: "lan-surface",
                matchedSource: blocked ? definition.Key : null);
            return Ok(blocked
                ? $"{definition.Label} blocked"
                : $"{definition.Label} restored");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException or InvalidOperationException)
        {
            return Error("lan_surface_failed", $"{definition.Label}: {ex.Message}");
        }
    }

    private LanAttackSurfaceToggleState StateFor(LanAttackSurfaceDefinition definition)
    {
        var registryBlocked = _store.IsBlocked(definition.Key);
        var wanted = _db.GetMeta(MetaPrefix + definition.Key) == "blocked";
        var ruleNames = definition.Rules.Select(r => r.Name).ToList();
        var existing = _firewall is { } fw
            ? ruleNames.Count(name => fw.RuleExists(name))
            : 0;
        var ruleBlocked = ruleNames.Count == 0 || existing == ruleNames.Count;
        var blocked = wanted && ruleBlocked && (definition.RegistryBacked ? registryBlocked : true);
        var status = blocked
            ? "Blocked"
            : wanted && (!ruleBlocked || (definition.RegistryBacked && !registryBlocked))
                ? $"Partial ({existing}/{ruleNames.Count} rules)"
                : "Allowed";

        return new LanAttackSurfaceToggleState(definition.Key, definition.Label, blocked, status, definition.BreakNote);
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) => new()
    {
        Ok = false,
        Message = message,
        ErrorCode = "hostsguard.error.v1/" + code,
    };

    private static readonly string SvchostPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "svchost.exe");

    private static readonly IReadOnlyList<LanAttackSurfaceDefinition> Definitions =
    [
        new(
            "llmnr",
            "LLMNR",
            "Legacy local-name lookup can stop; old printer/NAS names may need DNS names or IPs.",
            RegistryBacked: true,
            [
                Rule("HG_LAN_LLMNR_In", "In", "UDP", localPorts: "5355"),
                Rule("HG_LAN_LLMNR_Out", "Out", "UDP", remotePorts: "5355"),
            ]),
        new(
            "mdns",
            "mDNS",
            "AirPrint, Chromecast, HomeKit, and .local discovery may disappear until restored.",
            RegistryBacked: true,
            [
                Rule("HG_LAN_MDNS_In", "In", "UDP", localPorts: "5353"),
                Rule("HG_LAN_MDNS_Out", "Out", "UDP", remotePorts: "5353"),
            ]),
        new(
            "netbios-ns",
            "NetBIOS-NS",
            "Legacy Windows shares and NAS names may need direct hostnames or IP addresses.",
            RegistryBacked: true,
            [
                Rule("HG_LAN_NetBIOSNS_In", "In", "UDP", localPorts: "137"),
                Rule("HG_LAN_NetBIOSNS_Out", "Out", "UDP", remotePorts: "137"),
            ]),
        new(
            "ssdp",
            "SSDP / UPnP discovery",
            "UPnP discovery, media devices, and casting targets may stop appearing automatically.",
            RegistryBacked: true,
            [
                Rule("HG_LAN_SSDP_In", "In", "UDP", localPorts: "1900"),
                Rule("HG_LAN_SSDP_Out", "Out", "UDP", remotePorts: "1900"),
                Rule("HG_LAN_SSDP_Notify_In", "In", "TCP", localPorts: "2869"),
            ]),
        new(
            "wpad",
            "WPAD",
            "Automatic proxy discovery stops; explicit proxy settings keep working.",
            RegistryBacked: true,
            [
                Rule("HG_LAN_WPAD_Out", "Out", "TCP", remotePorts: "80", program: SvchostPath, serviceName: "WinHttpAutoProxySvc"),
            ]),
        new(
            "inbound-smb",
            "Inbound SMB",
            "Other devices cannot browse this PC's Windows file shares while this is blocked.",
            RegistryBacked: false,
            [
                Rule("HG_LAN_SMB_In", "In", "TCP", remoteAddr: "Any", localPorts: "139,445"),
            ]),
    ];

    private static LanRuleSpec Rule(
        string name,
        string direction,
        string protocol,
        string remoteAddr = "LocalSubnet",
        string remotePorts = "Any",
        string localPorts = "Any",
        string program = "",
        string serviceName = "")
        => new(name, direction, protocol, remoteAddr, remotePorts, localPorts, program, serviceName);

    private sealed record LanAttackSurfaceDefinition(
        string Key,
        string Label,
        string BreakNote,
        bool RegistryBacked,
        IReadOnlyList<LanRuleSpec> Rules);

    private sealed record LanRuleSpec(
        string Name,
        string Direction,
        string Protocol,
        string RemoteAddr,
        string RemotePorts,
        string LocalPorts,
        string Program,
        string ServiceName)
    {
        public FwRule ToFwRule()
            => new(
                Name,
                Direction,
                "Block",
                Enabled: true,
                RemoteAddr,
                Protocol,
                Program,
                "hostsguard",
                RemotePorts,
                ServiceName,
                LocalPorts);
    }
}
