using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Diagnostics;
using Microsoft.Win32;

namespace HostsGuard.Windows;

/// <summary>One row from the Windows DNS client resolver cache.</summary>
public sealed record DnsCacheRecord(string Name, string Type, int DataLength, uint Flags);

/// <summary>Resolver configuration and effective DNS state for one selectable adapter.</summary>
public sealed record DnsAdapterState(
    string Id,
    string Name,
    string Description,
    bool IsUp,
    bool IsVpn,
    bool UsesDhcp,
    IReadOnlyList<string> ConfiguredResolvers,
    IReadOnlyList<string> EffectiveResolvers);

/// <summary>An exact, restorable resolver snapshot for a selected set of adapters.</summary>
public sealed class DnsResolverSnapshot
{
    public DnsResolverSnapshot(IReadOnlyList<DnsAdapterState> adapters)
        : this(
            adapters,
            new Dictionary<string, DnsRegistryValue>(StringComparer.OrdinalIgnoreCase),
            new Dictionary<string, DnsDohAdapterSnapshot>(StringComparer.OrdinalIgnoreCase))
    {
    }

    internal DnsResolverSnapshot(
        IReadOnlyList<DnsAdapterState> adapters,
        IReadOnlyDictionary<string, DnsRegistryValue> registryValues,
        IReadOnlyDictionary<string, DnsDohAdapterSnapshot> dohSettings)
    {
        Adapters = adapters;
        RegistryValues = registryValues;
        DohSettings = dohSettings;
    }

    public IReadOnlyList<DnsAdapterState> Adapters { get; }
    internal IReadOnlyDictionary<string, DnsRegistryValue> RegistryValues { get; }
    internal IReadOnlyDictionary<string, DnsDohAdapterSnapshot> DohSettings { get; }
}

/// <summary>The adapters changed by a resolver mutation and their exact prior state.</summary>
public sealed record DnsResolverChange(
    DnsResolverSnapshot Prior,
    IReadOnlyList<DnsAdapterState> ChangedAdapters,
    IReadOnlyList<DnsDohTemplateStatus>? DohTemplates = null);

/// <summary>Result of a bounded A+AAAA resolver-health probe.</summary>
public sealed record DnsProbeResult(
    bool Success,
    TimeSpan RoundTrip,
    int Ipv4Count,
    int Ipv6Count,
    string Error);

/// <summary>DNS cache flush + resolver switching, interface-first for testability.</summary>
public interface IDnsConfig
{
    /// <summary>Flush the Windows DNS client cache. Returns false if the API refused.</summary>
    bool FlushCache();

    /// <summary>Flush one Windows DNS client cache entry by name.</summary>
    bool FlushCacheEntry(string name);

    /// <summary>Snapshot the Windows DNS client resolver cache.</summary>
    IReadOnlyList<DnsCacheRecord> GetCacheEntries(int limit, string? search);

    /// <summary>
    /// Set static DNS servers on all connected physical adapters (registry
    /// NameServer, the documented pre-SetInterfaceDnsSettings mechanism).
    /// Empty list resets to DHCP. Returns the adapters changed.
    /// </summary>
    IReadOnlyList<string> SetResolvers(IReadOnlyList<string> servers);

    /// <summary>List active adapters that can be configured, including VPN/tunnel adapters.</summary>
    IReadOnlyList<DnsAdapterState> ListResolverAdapters();

    /// <summary>Set resolvers on selected adapter IDs, returning their exact prior state.</summary>
    DnsResolverChange SetResolvers(IReadOnlyList<string> servers, IReadOnlyList<string> adapterIds);

    /// <summary>Restore an exact snapshot, including absent registry values and original kinds.</summary>
    void RestoreResolvers(DnsResolverSnapshot snapshot);

    /// <summary>Run one bounded A+AAAA lookup through the current Windows resolver path.</summary>
    Task<DnsProbeResult> ProbeAsync(string host, TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>Read-only per-adapter/per-endpoint resolver health matrix.</summary>
    Task<IReadOnlyList<DnsResolverHealthResult>> CheckResolverHealthAsync(
        string host,
        TimeSpan perProbeTimeout,
        CancellationToken cancellationToken);

    /// <summary>Resolver IPs currently carrying an interface-specific DoH property.</summary>
    IReadOnlySet<string> EncryptedResolvers();
}

internal sealed record DnsAdapterCandidate(
    string Id,
    string Name,
    string Description,
    NetworkInterfaceType Type,
    bool IsUp,
    bool HasUnicastAddress,
    IReadOnlyList<string> EffectiveResolvers);

internal sealed record DnsRegistryValue(bool Exists, object? Value, RegistryValueKind? Kind)
{
    public static DnsRegistryValue Absent { get; } = new(false, null, null);
}

internal interface IDnsAdapterSource
{
    IReadOnlyList<DnsAdapterCandidate> GetAdapters();
}

internal interface IDnsRegistryStore
{
    DnsRegistryValue Read(string adapterId);
    void Write(string adapterId, object value, RegistryValueKind kind);
    void Delete(string adapterId);
}

/// <summary>
/// Native DNS control: <c>dnsapi!DnsFlushResolverCache</c> for the cache and
/// per-interface registry NameServer values for resolver switching — replaces
/// the Python <c>ipconfig /flushdns</c> + <c>Set-DnsClientServerAddress</c> shelling.
/// Mutation requires elevation (the service has it).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DnsConfig : IDnsConfig
{
    private readonly IDnsAdapterSource _adapters;
    private readonly IDnsRegistryStore _registry;
    private readonly Func<bool> _flushCache;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolve;
    private readonly DnsResolverHealthProbe _healthProbe;
    private readonly IDohTemplateManager _dohTemplates;

    public DnsConfig()
        : this(
            new SystemDnsAdapterSource(),
            new SystemDnsRegistryStore(),
            () => DnsFlushResolverCache() != 0,
            (host, cancellationToken) => Dns.GetHostAddressesAsync(host, cancellationToken),
            dohTemplates: new WindowsDohTemplateManager())
    {
    }

    internal DnsConfig(
        IDnsAdapterSource adapters,
        IDnsRegistryStore registry,
        Func<bool>? flushCache = null,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null,
        IDnsResolverHealthTargetSource? healthTargets = null,
        IDnsResolverHealthTransport? healthTransport = null,
        IDohTemplateManager? dohTemplates = null)
    {
        _adapters = adapters;
        _registry = registry;
        _flushCache = flushCache ?? (() => true);
        _resolve = resolve ?? ((host, cancellationToken) => Dns.GetHostAddressesAsync(host, cancellationToken));
        _healthProbe = new DnsResolverHealthProbe(
            healthTargets ?? new WindowsDnsResolverHealthTargetSource(),
            healthTransport ?? new SystemDnsResolverHealthTransport());
        _dohTemplates = dohTemplates ?? new NullDohTemplateManager();
    }

    [DllImport("dnsapi.dll", SetLastError = false)]
    private static extern uint DnsFlushResolverCache();

    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCacheEntry_W", CharSet = CharSet.Unicode, SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DnsFlushResolverCacheEntry(string name);

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DnsGetCacheDataTable(out IntPtr cacheTable);

    [DllImport("dnsapi.dll", SetLastError = false)]
    private static extern void DnsFree(IntPtr data, int freeType);

    /// <summary><c>DnsFreeFlat</c> — free a flat dnsapi-heap allocation.</summary>
    private const int DnsFreeFlat = 0;

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DnsCacheEntryNative
    {
        public readonly IntPtr Next;
        public readonly IntPtr Name;
        public readonly ushort Type;
        public readonly ushort DataLength;
        public readonly uint Flags;
    }

    public bool FlushCache() => _flushCache();

    public bool FlushCacheEntry(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return DnsFlushResolverCacheEntry(name);
    }

    public IReadOnlyList<DnsCacheRecord> GetCacheEntries(int limit, string? search)
    {
        var max = limit <= 0 ? 500 : Math.Clamp(limit, 1, 5_000);
        var needle = (search ?? string.Empty).Trim();
        if (!DnsGetCacheDataTable(out var table) || table == IntPtr.Zero)
        {
            return Array.Empty<DnsCacheRecord>();
        }

        // Walk the WHOLE list even past the collection cap: every node (and its
        // dnsapi-heap name string) must be freed or each snapshot leaks natively.
        var entries = new List<DnsCacheRecord>();
        var current = table;
        var walked = 0;
        while (current != IntPtr.Zero && walked++ < 20_000)
        {
            var native = Marshal.PtrToStructure<DnsCacheEntryNative>(current);
            if (entries.Count < max)
            {
                var name = Marshal.PtrToStringUni(native.Name)?.TrimEnd('.') ?? string.Empty;
                var type = FormatDnsType(native.Type);
                if (name.Length != 0 &&
                    (needle.Length == 0 ||
                     name.Contains(needle, StringComparison.OrdinalIgnoreCase) ||
                     type.Contains(needle, StringComparison.OrdinalIgnoreCase)))
                {
                    entries.Add(new DnsCacheRecord(name, type, native.DataLength, native.Flags));
                }
            }

            if (native.Name != IntPtr.Zero)
            {
                DnsFree(native.Name, DnsFreeFlat);
            }

            DnsFree(current, DnsFreeFlat);
            current = native.Next;
        }

        return entries;
    }

    private static string FormatDnsType(ushort type) => type switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        48 => "DNSKEY",
        52 => "TLSA",
        64 => "SVCB",
        65 => "HTTPS",
        _ => type.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    public IReadOnlyList<string> SetResolvers(IReadOnlyList<string> servers)
    {
        // Legacy callers retain the old physical-adapter behavior. VPN/tunnel
        // interfaces are available only through the explicit-ID overload.
        var adapters = ListResolverAdapters().Where(adapter => !adapter.IsVpn).ToArray();
        if (adapters.Length == 0)
        {
            return Array.Empty<string>();
        }

        return SetResolvers(servers, adapters.Select(a => a.Id).ToArray())
            .ChangedAdapters
            .Select(a => a.Name)
            .ToArray();
    }

    public IReadOnlyList<DnsAdapterState> ListResolverAdapters()
        => EligibleAdapters()
            .Select(ToState)
            .OrderByDescending(a => a.IsVpn)
            .ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public DnsResolverChange SetResolvers(
        IReadOnlyList<string> servers,
        IReadOnlyList<string> adapterIds)
    {
        ArgumentNullException.ThrowIfNull(servers);
        ArgumentNullException.ThrowIfNull(adapterIds);

        var normalizedServers = servers.Select(ParseResolver).Distinct().ToArray();
        var selected = SelectAdapters(adapterIds);
        var prior = Capture(selected);
        var value = string.Join(",", normalizedServers);

        var dohStatus = new Dictionary<string, DnsDohTemplateStatus>(StringComparer.OrdinalIgnoreCase);
        ApplyTransaction(
            selected.Select(a => a.Id),
            adapterId =>
            {
                if (normalizedServers.Length == 0)
                {
                    _registry.Delete(adapterId);
                }
                else
                {
                    _registry.Write(adapterId, value, RegistryValueKind.String);
                }

                foreach (var status in _dohTemplates.Apply(adapterId, normalizedServers))
                {
                    dohStatus[status.Server] = status;
                }
            },
            prior);

        FlushCache();
        var changed = selected.Select(a =>
            new DnsAdapterState(
                a.Id,
                a.Name,
                a.Description,
                a.IsUp,
                IsVpnAdapter(a),
                normalizedServers.Length == 0,
                normalizedServers,
                a.EffectiveResolvers)).ToArray();
        return new DnsResolverChange(prior, changed, dohStatus.Values
            .OrderBy(status => status.Server, StringComparer.OrdinalIgnoreCase)
            .ToArray());
    }

    public void RestoreResolvers(DnsResolverSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var ids = snapshot.RegistryValues.Keys.ToArray();
        var currentValues = ids.ToDictionary(
            id => id,
            id => CloneRegistryValue(_registry.Read(id)),
            StringComparer.OrdinalIgnoreCase);
        var currentDoh = ids.ToDictionary(
            id => id,
            id => _dohTemplates.Capture(id),
            StringComparer.OrdinalIgnoreCase);
        var current = new DnsResolverSnapshot(snapshot.Adapters, currentValues, currentDoh);
        ApplyTransaction(ids, id =>
        {
            if (snapshot.DohSettings.TryGetValue(id, out var doh))
            {
                _dohTemplates.Restore(doh);
            }

            RestoreValue(id, snapshot.RegistryValues[id]);
        }, current);
        FlushCache();
    }

    public async Task<DnsProbeResult> ProbeAsync(
        string host,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        cancellationToken.ThrowIfCancellationRequested();
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var timer = Stopwatch.StartNew();
        try
        {
            var addresses = await _resolve(host.Trim(), timeoutSource.Token).ConfigureAwait(false);
            timer.Stop();
            var ipv4 = addresses.Count(a => a.AddressFamily == AddressFamily.InterNetwork);
            var ipv6 = addresses.Count(a => a.AddressFamily == AddressFamily.InterNetworkV6);
            return new DnsProbeResult(
                addresses.Length != 0,
                timer.Elapsed,
                ipv4,
                ipv6,
                addresses.Length == 0 ? "no_addresses" : string.Empty);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            timer.Stop();
            return new DnsProbeResult(false, timer.Elapsed, 0, 0, "timeout");
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            timer.Stop();
            return new DnsProbeResult(false, timer.Elapsed, 0, 0, ex.GetType().Name);
        }
    }

    public Task<IReadOnlyList<DnsResolverHealthResult>> CheckResolverHealthAsync(
        string host,
        TimeSpan perProbeTimeout,
        CancellationToken cancellationToken)
        => _healthProbe.CheckAsync(ListResolverAdapters(), host, perProbeTimeout, cancellationToken);

    public IReadOnlySet<string> EncryptedResolvers()
    {
        var resolvers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var adapter in ListResolverAdapters())
        {
            var snapshot = _dohTemplates.Capture(adapter.Id);
            if (!snapshot.Available)
            {
                continue;
            }

            foreach (var binding in snapshot.Bindings)
            {
                if (IPAddress.TryParse(binding.Server, out var address))
                {
                    resolvers.Add(address.ToString());
                }
            }
        }

        return resolvers;
    }

    private IReadOnlyList<DnsAdapterCandidate> EligibleAdapters()
        => _adapters.GetAdapters()
            .Where(a => a.IsUp && a.HasUnicastAddress && a.Type != NetworkInterfaceType.Loopback)
            .ToArray();

    private IReadOnlyList<DnsAdapterCandidate> SelectAdapters(IReadOnlyList<string> adapterIds)
    {
        var requested = adapterIds
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (requested.Length == 0)
        {
            throw new ArgumentException("At least one eligible adapter ID is required.", nameof(adapterIds));
        }

        var eligible = EligibleAdapters().ToDictionary(a => a.Id, StringComparer.OrdinalIgnoreCase);
        var unknown = requested.Where(id => !eligible.ContainsKey(id)).ToArray();
        if (unknown.Length != 0)
        {
            throw new ArgumentException($"Unknown or inactive adapter ID: {string.Join(", ", unknown)}", nameof(adapterIds));
        }

        return requested.Select(id => eligible[id]).ToArray();
    }

    private DnsResolverSnapshot Capture(IReadOnlyList<DnsAdapterCandidate> adapters)
    {
        var values = adapters.ToDictionary(
            a => a.Id,
            a => CloneRegistryValue(_registry.Read(a.Id)),
            StringComparer.OrdinalIgnoreCase);
        var doh = adapters.ToDictionary(
            a => a.Id,
            a => _dohTemplates.Capture(a.Id),
            StringComparer.OrdinalIgnoreCase);
        return new DnsResolverSnapshot(adapters.Select(ToState).ToArray(), values, doh);
    }

    private DnsAdapterState ToState(DnsAdapterCandidate adapter)
    {
        var configured = ParseConfigured(_registry.Read(adapter.Id));
        return new DnsAdapterState(
            adapter.Id,
            adapter.Name,
            adapter.Description,
            adapter.IsUp,
            IsVpnAdapter(adapter),
            configured.Count == 0,
            configured,
            adapter.EffectiveResolvers);
    }

    private void ApplyTransaction(
        IEnumerable<string> adapterIds,
        Action<string> mutation,
        DnsResolverSnapshot rollback)
    {
        try
        {
            foreach (var adapterId in adapterIds)
            {
                mutation(adapterId);
            }
        }
        catch (Exception mutationError)
        {
            var rollbackErrors = new List<Exception>();
            foreach (var prior in rollback.RegistryValues)
            {
                try
                {
                    if (rollback.DohSettings.TryGetValue(prior.Key, out var doh))
                    {
                        _dohTemplates.Restore(doh);
                    }

                    RestoreValue(prior.Key, prior.Value);
                }
                catch (Exception rollbackError)
                {
                    rollbackErrors.Add(rollbackError);
                }
            }

            _flushCache();
            if (rollbackErrors.Count != 0)
            {
                rollbackErrors.Insert(0, mutationError);
                throw new AggregateException("DNS resolver mutation and rollback failed.", rollbackErrors);
            }

            throw;
        }
    }

    private void RestoreValue(string adapterId, DnsRegistryValue value)
    {
        if (!value.Exists)
        {
            _registry.Delete(adapterId);
            return;
        }

        _registry.Write(adapterId, CloneValue(value.Value)!, value.Kind!.Value);
    }

    private static DnsRegistryValue CloneRegistryValue(DnsRegistryValue value)
        => new(value.Exists, CloneValue(value.Value), value.Kind);

    private static object? CloneValue(object? value) => value switch
    {
        byte[] bytes => bytes.ToArray(),
        string[] strings => strings.ToArray(),
        _ => value,
    };

    private static IReadOnlyList<string> ParseConfigured(DnsRegistryValue value)
    {
        if (!value.Exists)
        {
            return Array.Empty<string>();
        }

        var entries = value.Value switch
        {
            string text => text.Split(
                [',', ' ', ';'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            string[] strings => strings,
            _ => Array.Empty<string>(),
        };
        return entries
            .Where(server => IPAddress.TryParse(server, out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string ParseResolver(string server)
    {
        if (!IPAddress.TryParse(server?.Trim(), out var address))
        {
            throw new ArgumentException($"Invalid DNS resolver address: {server}", nameof(server));
        }

        return address.ToString();
    }

    private static bool IsVpnAdapter(DnsAdapterCandidate adapter)
    {
        if (adapter.Type is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp)
        {
            return true;
        }

        var identity = $"{adapter.Name} {adapter.Description}";
        return VpnMarkers.Any(marker => identity.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static readonly string[] VpnMarkers =
        ["VPN", "WireGuard", "OpenVPN", "Tailscale", "ZeroTier", "TAP-Windows", "TUN Adapter"];

    /// <summary>The machine's currently configured resolver IPs (all adapters).</summary>
    public static IReadOnlyList<IPAddress> CurrentResolvers()
        => NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().DnsAddresses)
            .Distinct()
            .ToList();

    // ─── Encrypted-DNS (DoH) posture (NET-112) ───────────────────────────────

    private const string DohInterfacesKey =
        @"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters";

    /// <summary>
    /// True when a configured DoH server requires encryption with no plaintext
    /// fallback (the "encrypted DNS only" posture). Windows stores this per DoH
    /// server as <c>DohFlags</c>: 2 (and the 3 variant) mean require-no-fallback;
    /// 1 is opportunistic (fallback allowed). Best-effort — see
    /// <see cref="RequiresEncryption"/>.
    /// </summary>
    public static bool RequiresEncryption(int dohFlags) => dohFlags is 2 or 3;

    /// <summary>
    /// Best-effort probe of whether the machine is in an encrypted-DNS-only posture
    /// (any active interface has a DoH server flagged require-no-fallback). Blocking
    /// encrypted DNS on such a machine can sever name resolution unless the resolver
    /// is exempted — the caller should warn. Never throws.
    /// </summary>
    public static bool IsEncryptedDnsOnly()
    {
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(DohInterfacesKey);
            if (root is null)
            {
                return false;
            }

            foreach (var ifaceName in root.GetSubKeyNames())
            {
                // …\{iface}\DohInterfaceSettings\Doh(6)?\{serverIp} → DohFlags DWORD.
                using var doh = root.OpenSubKey($@"{ifaceName}\DohInterfaceSettings");
                if (doh is null)
                {
                    continue;
                }

                foreach (var family in doh.GetSubKeyNames()) // "Doh", "Doh6"
                {
                    using var servers = doh.OpenSubKey(family);
                    if (servers is null)
                    {
                        continue;
                    }

                    foreach (var server in servers.GetSubKeyNames())
                    {
                        using var s = servers.OpenSubKey(server);
                        if (s?.GetValue("DohFlags") is int flags && RequiresEncryption(flags))
                        {
                            return true;
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Best-effort: an unreadable registry means we simply don't warn.
        }

        return false;
    }

    // ─── DNR: Discovery of Network-designated Resolvers, RFC 9463 (NET-173) ──────

    private const string DnscacheParametersKey =
        @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";

    /// <summary>
    /// Best-effort read of the Windows DNR client switch
    /// (<c>Dnscache\Parameters\EnableDnr</c> DWORD = 1). When on, Windows will
    /// auto-configure encrypted resolvers advertised by the network via DHCP/RA,
    /// so a network can silently steer DNS — HostsGuard surfaces this. Never throws.
    /// </summary>
    public static bool IsDnrEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DnscacheParametersKey);
            return key?.GetValue("EnableDnr") is int v && v != 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }
}

[SupportedOSPlatform("windows")]
internal sealed class SystemDnsAdapterSource : IDnsAdapterSource
{
    public IReadOnlyList<DnsAdapterCandidate> GetAdapters()
    {
        var adapters = new List<DnsAdapterCandidate>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            IPInterfaceProperties properties;
            try
            {
                properties = nic.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            adapters.Add(new DnsAdapterCandidate(
                nic.Id,
                nic.Name,
                nic.Description,
                nic.NetworkInterfaceType,
                nic.OperationalStatus == OperationalStatus.Up,
                properties.UnicastAddresses.Any(a =>
                    a.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6),
                properties.DnsAddresses.Select(a => a.ToString()).Distinct().ToArray()));
        }

        return adapters;
    }
}

[SupportedOSPlatform("windows")]
internal sealed class SystemDnsRegistryStore : IDnsRegistryStore
{
    private const string InterfacesKey =
        @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    public DnsRegistryValue Read(string adapterId)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKey}\{adapterId}");
        if (key is null || !key.GetValueNames().Contains("NameServer", StringComparer.OrdinalIgnoreCase))
        {
            return DnsRegistryValue.Absent;
        }

        var value = key.GetValue("NameServer", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return new DnsRegistryValue(true, value, key.GetValueKind("NameServer"));
    }

    public void Write(string adapterId, object value, RegistryValueKind kind)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKey}\{adapterId}", writable: true)
            ?? throw new IOException($"DNS registry key was not found for adapter '{adapterId}'.");
        key.SetValue("NameServer", value, kind);
    }

    public void Delete(string adapterId)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKey}\{adapterId}", writable: true)
            ?? throw new IOException($"DNS registry key was not found for adapter '{adapterId}'.");
        key.DeleteValue("NameServer", throwOnMissingValue: false);
    }
}
