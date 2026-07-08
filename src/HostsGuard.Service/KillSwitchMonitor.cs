using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Text.Json;
using HostsGuard.Contracts;
using HostsGuard.Data;
using HostsGuard.Windows;

namespace HostsGuard.Service;

/// <summary>
/// VPN-presence kill-switch (NET-119): when armed and the chosen VPN adapter is
/// <b>down</b>, force default-outbound Block on every firewall profile so traffic
/// can't leak outside the tunnel; when the adapter comes back up, restore the exact
/// prior per-profile posture. Opt-in, off by default.
///
/// <para>Enforcement flips the profile <i>default</i> action (like the consent-mode
/// rails), which preserves explicit Allow rules — so an existing allow rule for the
/// VPN client keeps the tunnel able to reconnect. The engaged posture and the saved
/// prior are persisted, so a service restart while engaged neither loses the real
/// prior nor leaves a stale block once the VPN returns.</para>
///
/// <para>The adapter-presence probe is injected so the logic is unit-testable
/// without a real NIC; production wires it to <see cref="NetworkAdapters.IsUp"/>.</para>
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class KillSwitchMonitor : IDisposable
{
    private readonly IFirewallEngine _fw;
    private readonly HostsDatabase _db;
    private readonly Func<string, bool> _isAdapterUp;
    private readonly string _statePath;
    private readonly System.Threading.Timer _debounce;
    private readonly object _gate = new();
    private KillSwitchState _state;
    private bool _armed;
    private bool _subscribed;

    public KillSwitchMonitor(IFirewallEngine fw, HostsDatabase db, Func<string, bool> isAdapterUp, string dataDir)
    {
        _fw = fw ?? throw new ArgumentNullException(nameof(fw));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _isAdapterUp = isAdapterUp ?? throw new ArgumentNullException(nameof(isAdapterUp));
        _statePath = Path.Combine(dataDir, "killswitch_state.json");
        _state = LoadState();
        _armed = _state.PriorOutboundBlock is not null; // survive a restart-while-engaged
        _debounce = new System.Threading.Timer(_ => Evaluate(), null, Timeout.Infinite, Timeout.Infinite);
    }

    public Action? BeforeEngage { get; set; }

    public Action? AfterEngage { get; set; }

    public Action? AfterRelease { get; set; }

    /// <summary>Whether the kill-switch is turned on (may or may not be engaged right now).</summary>
    public bool Enabled
    {
        get { lock (_gate) { return _state.Enabled; } }
    }

    /// <summary>The name/description substring identifying the VPN adapter to watch.</summary>
    public string Adapter
    {
        get { lock (_gate) { return _state.Adapter; } }
    }

    /// <summary>Whether block-all is currently being enforced because the VPN is down.</summary>
    public bool IsEngaged
    {
        get { lock (_gate) { return _armed; } }
    }

    public void Start()
    {
        lock (_gate)
        {
            if (!_subscribed)
            {
                NetworkChange.NetworkAddressChanged += OnNetworkChanged;
                _subscribed = true;
            }
        }

        Evaluate(); // immediate: (re)establish the correct posture at startup
    }

    private void OnNetworkChanged(object? sender, EventArgs e) => Kick();

    private void Kick() => _debounce.Change(TimeSpan.FromSeconds(3), Timeout.InfiniteTimeSpan);

    /// <summary>Turn the kill-switch on/off and choose the adapter; re-evaluates immediately.</summary>
    public Ack Configure(bool enabled, string adapter)
    {
        adapter = (adapter ?? string.Empty).Trim();
        if (enabled && adapter.Length == 0)
        {
            return new Ack
            {
                Ok = false,
                Message = "choose a VPN adapter before enabling the kill-switch",
                ErrorCode = "hostsguard.error.v1/invalid_adapter",
            };
        }

        lock (_gate)
        {
            _state.Enabled = enabled;
            _state.Adapter = adapter;
            SaveState();
        }

        _db.LogEvent("killswitch", enabled ? "enabled" : "disabled", details: adapter, reason: "killswitch");
        Evaluate();
        return new Ack
        {
            Ok = true,
            Message = enabled
                ? $"kill-switch ON — blocks all outbound whenever '{adapter}' is down"
                : "kill-switch OFF",
        };
    }

    /// <summary>Resolve adapter presence and arm/disarm block-all accordingly.</summary>
    public void Evaluate()
    {
        lock (_gate)
        {
            // Off, or enabled-but-unconfigured, must never enforce a block.
            if (!_state.Enabled || _state.Adapter.Length == 0)
            {
                Disarm();
                return;
            }

            bool up;
            try
            {
                up = _isAdapterUp(_state.Adapter);
            }
            catch (NetworkInformationException)
            {
                return; // transient enumeration failure — leave posture as-is
            }

            if (up)
            {
                Disarm();
            }
            else
            {
                Arm();
            }
        }
    }

    // Caller holds _gate.
    private void Arm()
    {
        if (_armed)
        {
            return;
        }

        // Capture the real prior posture only once (a restart mid-engagement keeps
        // the original, never the block-all we ourselves applied).
        BeforeEngage?.Invoke();
        _state.PriorOutboundBlock ??= _fw.GetPosture().ToDictionary(p => p.Name, p => p.OutboundBlock, StringComparer.Ordinal);
        _fw.SetDefaultOutboundBlock(true);
        _armed = true;
        SaveState();
        _db.LogEvent("killswitch", "engaged", details: _state.Adapter, reason: "vpn_down");
        _db.AddAlert(
            "kill_switch",
            "critical",
            "VPN kill-switch engaged",
            _state.Adapter,
            $"Default outbound is blocked because '{_state.Adapter}' is down.",
            action: "engaged");
        AfterEngage?.Invoke();
    }

    // Caller holds _gate.
    private void Disarm()
    {
        if (!_armed)
        {
            return;
        }

        if (_state.PriorOutboundBlock is { } prior)
        {
            _fw.SetDefaultOutboundBlock(prior);
        }

        _state.PriorOutboundBlock = null;
        _armed = false;
        SaveState();
        _db.LogEvent("killswitch", "released", details: _state.Adapter, reason: "vpn_up");
        AfterRelease?.Invoke();
    }

    private KillSwitchState LoadState()
    {
        try
        {
            if (File.Exists(_statePath))
            {
                var loaded = JsonSerializer.Deserialize<KillSwitchState>(File.ReadAllText(_statePath));
                if (loaded is not null)
                {
                    return loaded;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            // Corrupt/locked state — fall back to a safe default (off).
        }

        return new KillSwitchState();
    }

    private void SaveState()
    {
        try
        {
            var tmp = _statePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_state));
            File.Move(tmp, _statePath, overwrite: true);
        }
        catch (IOException)
        {
            // Best-effort persistence; in-memory state remains authoritative this run.
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_subscribed)
            {
                NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
                _subscribed = false;
            }
        }

        _debounce.Dispose();
    }

    private sealed class KillSwitchState
    {
        public bool Enabled { get; set; }
        public string Adapter { get; set; } = string.Empty;
        public Dictionary<string, bool>? PriorOutboundBlock { get; set; }
    }
}
