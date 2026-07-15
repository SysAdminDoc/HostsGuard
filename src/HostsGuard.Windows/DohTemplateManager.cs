using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace HostsGuard.Windows;

/// <summary>The effective encrypted-DNS posture applied for one resolver address.</summary>
public sealed record DnsDohTemplateStatus(
    string Server,
    string Template,
    bool Encrypted,
    bool AllowsPlaintextFallback,
    string Detail);

internal sealed record DnsDohBinding(string Server, string Template, ulong Flags);

internal sealed record DnsDohAdapterSnapshot(
    string AdapterId,
    bool Available,
    IReadOnlyList<DnsDohBinding> Bindings)
{
    public static DnsDohAdapterSnapshot Unavailable(string adapterId) => new(adapterId, false, []);
}

internal interface IDohTemplateManager
{
    DnsDohAdapterSnapshot Capture(string adapterId);

    IReadOnlyList<DnsDohTemplateStatus> Apply(string adapterId, IReadOnlyList<string> servers);

    void Restore(DnsDohAdapterSnapshot snapshot);
}

internal sealed class NullDohTemplateManager : IDohTemplateManager
{
    public DnsDohAdapterSnapshot Capture(string adapterId) => DnsDohAdapterSnapshot.Unavailable(adapterId);

    public IReadOnlyList<DnsDohTemplateStatus> Apply(string adapterId, IReadOnlyList<string> servers)
        => servers.Select(server => DohTemplateCatalog.FindCurated(server) is { } template
            ? new DnsDohTemplateStatus(server, template, false, true, "registration_unavailable")
            : new DnsDohTemplateStatus(server, string.Empty, false, true, "template_missing"))
            .ToArray();

    public void Restore(DnsDohAdapterSnapshot snapshot)
    {
    }
}

/// <summary>
/// Curated public-resolver DoH templates used when Windows has no built-in entry.
/// The addresses and endpoints are published by Cloudflare, Google, and Quad9.
/// </summary>
public static class DohTemplateCatalog
{
    private const string WellKnownServersKey =
        @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers";

    private static readonly IReadOnlyDictionary<string, string> Curated =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["1.1.1.1"] = "https://cloudflare-dns.com/dns-query",
            ["1.0.0.1"] = "https://cloudflare-dns.com/dns-query",
            ["2606:4700:4700::1111"] = "https://cloudflare-dns.com/dns-query",
            ["2606:4700:4700::1001"] = "https://cloudflare-dns.com/dns-query",
            ["8.8.8.8"] = "https://dns.google/dns-query",
            ["8.8.4.4"] = "https://dns.google/dns-query",
            ["2001:4860:4860::8888"] = "https://dns.google/dns-query",
            ["2001:4860:4860::8844"] = "https://dns.google/dns-query",
            ["9.9.9.9"] = "https://dns.quad9.net/dns-query",
            ["149.112.112.112"] = "https://dns.quad9.net/dns-query",
            ["2620:fe::fe"] = "https://dns.quad9.net/dns-query",
            ["2620:fe::9"] = "https://dns.quad9.net/dns-query",
        };

    public static string? FindCurated(string server)
        => IPAddress.TryParse(server, out var address) && Curated.TryGetValue(address.ToString(), out var template)
            ? template
            : null;

    internal static string? FindSystemOrCurated(string server)
    {
        if (!IPAddress.TryParse(server, out var address))
        {
            return null;
        }

        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(WellKnownServersKey);
            using var key = root?.OpenSubKey(address.ToString());
            if (ValidateTemplate(key?.GetValue("Template") as string) is { } systemTemplate)
            {
                return systemTemplate;
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // The service normally reads this key. The curated table remains a
            // deterministic fallback when policy prevents registry inspection.
        }

        return FindCurated(address.ToString());
    }

    internal static string? ValidateTemplate(string? template)
        => Uri.TryCreate(template, UriKind.Absolute, out var uri) &&
           uri.Scheme == Uri.UriSchemeHttps &&
           !string.IsNullOrWhiteSpace(uri.Host)
            ? uri.AbsoluteUri
            : null;
}

/// <summary>
/// Applies per-interface DoH server properties through the documented
/// SetInterfaceDnsSettings API. Existing settings are captured from the same
/// registry projection Windows exposes for rollback and health inspection.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsDohTemplateManager : IDohTemplateManager
{
    private const string InterfaceParameters =
        @"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters";
    private const uint InterfaceSettingsVersion3 = 3;
    private const uint ServerPropertyVersion1 = 1;
    private const ulong SettingIpv6 = 0x0001;
    private const ulong SettingDoh = 0x1000;
    private const ulong DohEnable = 0x0002;
    private const ulong DohFallbackToUdp = 0x0004;
    private const ulong DohAutoUpgradeServer = 0x0008;
    private const int DnsServerDohProperty = 1;

    public DnsDohAdapterSnapshot Capture(string adapterId)
    {
        if (!Guid.TryParse(adapterId.Trim('{', '}'), out _) || !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041))
        {
            return DnsDohAdapterSnapshot.Unavailable(adapterId);
        }

        try
        {
            var bindings = new List<DnsDohBinding>();
            using var root = Registry.LocalMachine.OpenSubKey(
                $@"{InterfaceParameters}\{NormalizeAdapterId(adapterId)}\DohInterfaceSettings");
            ReadFamily(root, "Doh", bindings);
            ReadFamily(root, "Doh6", bindings);
            return new DnsDohAdapterSnapshot(adapterId, true, bindings);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return DnsDohAdapterSnapshot.Unavailable(adapterId);
        }
    }

    public IReadOnlyList<DnsDohTemplateStatus> Apply(string adapterId, IReadOnlyList<string> servers)
    {
        var current = Capture(adapterId);
        var templates = servers.ToDictionary(
            server => server,
            DohTemplateCatalog.FindSystemOrCurated,
            StringComparer.OrdinalIgnoreCase);
        if (!current.Available)
        {
            return templates.Select(pair => pair.Value is null
                ? new DnsDohTemplateStatus(pair.Key, string.Empty, false, true, "template_missing")
                : new DnsDohTemplateStatus(pair.Key, pair.Value, false, true, "registration_unavailable"))
                .ToArray();
        }

        try
        {
            ApplyDesired(adapterId, servers, templates, current.Bindings);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw new IOException("Windows DoH interface configuration is unavailable.", ex);
        }
        return templates.Select(pair => pair.Value is null
            ? new DnsDohTemplateStatus(pair.Key, string.Empty, false, true, "template_missing")
            : new DnsDohTemplateStatus(pair.Key, pair.Value, true, true, "auto_upgrade_enabled"))
            .ToArray();
    }

    public void Restore(DnsDohAdapterSnapshot snapshot)
    {
        if (!snapshot.Available)
        {
            return;
        }

        var current = Capture(snapshot.AdapterId);
        if (!current.Available)
        {
            throw new IOException("Unable to capture current DoH interface settings for rollback.");
        }

        var servers = snapshot.Bindings.Select(binding => binding.Server)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var desired = snapshot.Bindings.ToDictionary(
            binding => binding.Server,
            binding => (string?)binding.Template,
            StringComparer.OrdinalIgnoreCase);
        try
        {
            ApplyDesired(snapshot.AdapterId, servers, desired, current.Bindings, snapshot.Bindings);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw new IOException("Windows DoH interface rollback is unavailable.", ex);
        }
    }

    private static void ApplyDesired(
        string adapterId,
        IReadOnlyList<string> servers,
        IReadOnlyDictionary<string, string?> templates,
        IReadOnlyList<DnsDohBinding> current,
        IReadOnlyList<DnsDohBinding>? exactBindings = null)
    {
        var guid = Guid.Parse(adapterId.Trim('{', '}'));
        foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
        {
            var desiredServers = servers.Where(server =>
                    IPAddress.TryParse(server, out var address) && address.AddressFamily == family)
                .ToArray();
            var existingServers = current.Where(binding =>
                    IPAddress.TryParse(binding.Server, out var address) && address.AddressFamily == family)
                .Select(binding => binding.Server)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var callServers = desiredServers.Length != 0 ? desiredServers : existingServers;
            if (callServers.Length == 0)
            {
                continue;
            }

            var bindings = exactBindings is null
                ? callServers.Select(server => templates.TryGetValue(server, out var template) && template is not null
                    ? new DnsDohBinding(server, template, DohEnable | DohFallbackToUdp | DohAutoUpgradeServer)
                    : null).Where(binding => binding is not null).Cast<DnsDohBinding>().ToArray()
                : exactBindings.Where(binding => callServers.Contains(binding.Server, StringComparer.OrdinalIgnoreCase)).ToArray();
            SetFamily(guid, family, callServers, bindings);
        }
    }

    private static void SetFamily(
        Guid adapterId,
        AddressFamily family,
        IReadOnlyList<string> servers,
        IReadOnlyList<DnsDohBinding> bindings)
    {
        var allocations = new List<IntPtr>();
        try
        {
            var nameServer = Marshal.StringToHGlobalUni(string.Join(',', servers));
            allocations.Add(nameServer);
            var propertySize = Marshal.SizeOf<DnsServerPropertyNative>();
            var properties = bindings.Count == 0
                ? IntPtr.Zero
                : Marshal.AllocHGlobal(propertySize * bindings.Count);
            if (properties != IntPtr.Zero)
            {
                allocations.Add(properties);
            }

            for (var i = 0; i < bindings.Count; i++)
            {
                var binding = bindings[i];
                var template = Marshal.StringToHGlobalUni(binding.Template);
                allocations.Add(template);
                var doh = Marshal.AllocHGlobal(Marshal.SizeOf<DnsDohServerSettingsNative>());
                allocations.Add(doh);
                Marshal.StructureToPtr(new DnsDohServerSettingsNative
                {
                    Template = template,
                    Flags = binding.Flags,
                }, doh, false);
                var serverIndex = Array.FindIndex(servers.ToArray(), server =>
                    string.Equals(server, binding.Server, StringComparison.OrdinalIgnoreCase));
                Marshal.StructureToPtr(new DnsServerPropertyNative
                {
                    Version = ServerPropertyVersion1,
                    ServerIndex = checked((uint)serverIndex),
                    Type = DnsServerDohProperty,
                    Property = doh,
                }, IntPtr.Add(properties, i * propertySize), false);
            }

            var settings = new DnsInterfaceSettings3Native
            {
                Version = InterfaceSettingsVersion3,
                Flags = SettingDoh | (family == AddressFamily.InterNetworkV6 ? SettingIpv6 : 0),
                NameServer = nameServer,
                ServerPropertyCount = checked((uint)bindings.Count),
                ServerProperties = properties,
            };
            var error = SetInterfaceDnsSettings(adapterId, ref settings);
            if (error != 0)
            {
                throw new IOException(
                    $"SetInterfaceDnsSettings failed for {adapterId} ({family}), Windows error {error}.");
            }
        }
        finally
        {
            for (var i = allocations.Count - 1; i >= 0; i--)
            {
                Marshal.FreeHGlobal(allocations[i]);
            }
        }
    }

    private static void ReadFamily(RegistryKey? root, string family, List<DnsDohBinding> bindings)
    {
        using var servers = root?.OpenSubKey(family);
        if (servers is null)
        {
            return;
        }

        foreach (var server in servers.GetSubKeyNames())
        {
            using var key = servers.OpenSubKey(server);
            var template = DohTemplateCatalog.ValidateTemplate(key?.GetValue("DohTemplate") as string);
            if (template is null)
            {
                continue;
            }

            var registryFlags = key?.GetValue("DohFlags") is int flags ? flags : 1;
            var nativeFlags = DohEnable | DohAutoUpgradeServer |
                              (DnsConfig.RequiresEncryption(registryFlags) ? 0 : DohFallbackToUdp);
            bindings.Add(new DnsDohBinding(server, template, nativeFlags));
        }
    }

    private static string NormalizeAdapterId(string adapterId)
        => "{" + Guid.Parse(adapterId.Trim('{', '}')).ToString("D") + "}";

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint SetInterfaceDnsSettings(Guid interfaceId, ref DnsInterfaceSettings3Native settings);

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsDohServerSettingsNative
    {
        public IntPtr Template;
        public ulong Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsServerPropertyNative
    {
        public uint Version;
        public uint ServerIndex;
        public int Type;
        public IntPtr Property;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsInterfaceSettings3Native
    {
        public uint Version;
        public ulong Flags;
        public IntPtr Domain;
        public IntPtr NameServer;
        public IntPtr SearchList;
        public uint RegistrationEnabled;
        public uint RegisterAdapterName;
        public uint EnableLlmnr;
        public uint QueryAdapterName;
        public IntPtr ProfileNameServer;
        public uint DisableUnconstrainedQueries;
        public IntPtr SupplementalSearchList;
        public uint ServerPropertyCount;
        public IntPtr ServerProperties;
        public uint ProfileServerPropertyCount;
        public IntPtr ProfileServerProperties;
    }
}
