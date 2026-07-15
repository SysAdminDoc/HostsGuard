using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using HostsGuard.Core;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// Auto-activates the profile mapped to the joined network (NET-083). Listens
/// for network-address changes, resolves the current fingerprint, and — when a
/// mapping exists and the target profile isn't already active — applies it.
/// The switch itself routes through <see cref="PolicyServiceImpl.ApplyProfile"/>
/// so it's identical to a manual switch (recoverable, logged). Debounced so a
/// flurry of adapter events causes one evaluation.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NetworkProfileWatcher : IDisposable
{
    private readonly ServiceState _state;
    private readonly INetworkIdentity _identity;
    private readonly Action<string> _applyProfile;
    private readonly System.Threading.Timer _debounce;
    private string _lastIdentity = string.Empty;

    public NetworkProfileWatcher(ServiceState state, INetworkIdentity identity, Action<string> applyProfile)
    {
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _applyProfile = applyProfile ?? throw new ArgumentNullException(nameof(applyProfile));
        _debounce = new System.Threading.Timer(_ => Evaluate(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public void Start()
    {
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        Kick(); // evaluate the current network at startup
    }

    private void OnNetworkChanged(object? sender, EventArgs e) => Kick();

    private void Kick() => _debounce.Change(TimeSpan.FromSeconds(3), Timeout.InfiniteTimeSpan);

    /// <summary>Resolve the current network and switch to its mapped profile if needed.</summary>
    public void Evaluate()
    {
        NetworkFingerprint? net;
        try
        {
            net = _identity.Current();
        }
        catch (NetworkInformationException)
        {
            return;
        }

        if (net is null)
        {
            return;
        }

        var identity = ToIdentity(net);
        var identityKey = string.Join('\n',
            identity.Fingerprint,
            identity.GatewayMac,
            identity.Ssid,
            identity.InterfaceName,
            identity.DnsSuffix,
            identity.VpnPresent);
        if (identityKey == _lastIdentity)
        {
            return;
        }

        _lastIdentity = identityKey;
        var rules = LoadRules(_state);

        var match = NetworkProfileMatcher.Match(identity, rules);
        if (match is null)
        {
            if (DescribeGatewayDrift(identity, rules) is { } drift)
            {
                _state.Db.TryAddAlertOnce(
                    "network_gateway_drift",
                    "warning",
                    "Gateway changed on a known Wi-Fi network",
                    $"{net.Ssid} / current gateway {drift.CurrentGatewayId}",
                    $"SSID '{net.Ssid}' previously used saved gateway {drift.SavedGatewayId}; " +
                    $"the current gateway is {drift.CurrentGatewayId}. This may indicate network " +
                    "impersonation or a router replacement. Verify the router or access point. " +
                    "If the replacement is expected, update the saved network profile mapping.",
                    action: "gateway_changed");
                return;
            }

            _state.Db.AddAlert(
                "unknown_lan",
                "warning",
                "Unknown LAN gateway",
                string.IsNullOrWhiteSpace(net.Label) ? net.Fingerprint : net.Label,
                $"Network fingerprint {net.Fingerprint} is not mapped to a saved profile.",
                action: "unknown_network");
            return;
        }

        var profile = match.Profile;
        if (_state.Db.GetMeta("active_profile") == profile)
        {
            return;
        }

        _state.Db.LogEvent(net.Label, "network_profile_auto", details: $"{Describe(match)} → {profile}");
        _applyProfile(profile);
    }

    internal static NetworkProfileIdentity ToIdentity(NetworkFingerprint network) => new(
        network.Fingerprint,
        network.GatewayMac,
        network.Ssid,
        network.InterfaceName,
        network.DnsSuffix,
        network.VpnPresent);

    internal static IReadOnlyList<NetworkProfileMatchRule> LoadRules(ServiceState state)
    {
        var rules = new List<NetworkProfileMatchRule>();
        var savedProfiles = state.Db.ListProfiles().ToHashSet(StringComparer.Ordinal);
        foreach (var (fingerprint, mappedProfile, label) in state.Db.GetNetworkProfiles())
        {
            if (!savedProfiles.Contains(mappedProfile))
            {
                continue;
            }

            try
            {
                rules.Add(NetworkProfileSelectorCodec.Decode(fingerprint, mappedProfile, label));
            }
            catch (FormatException)
            {
                // Malformed additive selectors are inert. Legacy plain values
                // decode without entering this branch.
            }
        }

        return rules;
    }

    internal static NetworkGatewayDrift? DescribeGatewayDrift(
        NetworkProfileIdentity identity,
        IEnumerable<NetworkProfileMatchRule> rules)
    {
        var saved = NetworkProfileMatcher.FindSameSsidGatewayDrift(identity, rules);
        if (saved is null)
        {
            return null;
        }

        var useMac = !string.IsNullOrWhiteSpace(saved.GatewayMac)
            && !string.IsNullOrWhiteSpace(identity.GatewayMac);
        var savedValue = useMac ? NormalizeMac(saved.GatewayMac) : saved.Fingerprint.Trim().ToUpperInvariant();
        var currentValue = useMac ? NormalizeMac(identity.GatewayMac) : identity.Fingerprint.Trim().ToUpperInvariant();
        return new NetworkGatewayDrift(StableId(savedValue), StableId(currentValue));
    }

    private static string NormalizeMac(string value) =>
        string.Concat(value.Where(Uri.IsHexDigit)).ToUpperInvariant();

    private static string StableId(string value)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(digest.AsSpan(0, 6));
    }

    private static string Describe(NetworkProfileMatchRule rule)
    {
        var signals = new List<string>();
        Add(signals, "gateway", rule.GatewayMac);
        Add(signals, "fingerprint", rule.Fingerprint);
        Add(signals, "ssid", rule.Ssid);
        Add(signals, "dns", rule.DnsSuffix);
        Add(signals, "interface", rule.InterfaceName);
        if (rule.VpnPresent.HasValue)
        {
            signals.Add($"vpn={rule.VpnPresent.Value.ToString().ToLowerInvariant()}");
        }

        return string.Join(", ", signals);
    }

    private static void Add(List<string> signals, string name, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            signals.Add($"{name}={value}");
        }
    }

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        _debounce.Dispose();
    }
}

internal sealed record NetworkGatewayDrift(string SavedGatewayId, string CurrentGatewayId);
