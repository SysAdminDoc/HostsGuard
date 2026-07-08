using System.Net.NetworkInformation;
using System.Runtime.Versioning;
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
    private string _lastFingerprint = string.Empty;

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

        if (net is null || net.Fingerprint == _lastFingerprint)
        {
            return;
        }

        _lastFingerprint = net.Fingerprint;
        var profile = _state.Db.GetProfileForNetwork(net.Fingerprint);
        if (string.IsNullOrEmpty(profile))
        {
            _state.Db.AddAlert(
                "unknown_lan",
                "warning",
                "Unknown LAN gateway",
                string.IsNullOrWhiteSpace(net.Label) ? net.Fingerprint : net.Label,
                $"Network fingerprint {net.Fingerprint} is not mapped to a saved profile.",
                action: "unknown_network");
            return;
        }

        if (_state.Db.GetMeta("active_profile") == profile || !_state.Db.ListProfiles().Contains(profile))
        {
            return;
        }

        _state.Db.LogEvent(net.Label, "network_profile_auto", details: $"{net.Fingerprint} → {profile}");
        _applyProfile(profile);
    }

    public void Dispose()
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        _debounce.Dispose();
    }
}
