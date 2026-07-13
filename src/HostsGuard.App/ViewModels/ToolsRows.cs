using CommunityToolkit.Mvvm.ComponentModel;
using HostsGuard.App.Services;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.App.ViewModels;

/// <summary>Editable row in the scheduled-blocking editor.</summary>
public sealed partial class ScheduleRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _target = string.Empty;

    [ObservableProperty]
    private string _daysText = string.Empty; // "Mon,Tue" or "0,1"

    [ObservableProperty]
    private string _start = "22:00";

    [ObservableProperty]
    private string _end = "06:00";

    /// <summary>Parse day names or indices into the proto 0=Mon..6=Sun form.</summary>
    public IReadOnlyList<int> ParseDays()
    {
        var days = new List<int>();
        foreach (var token in DaysText.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(token, out var idx))
            {
                days.Add(idx);
                continue;
            }

            var named = Scheduling.Weekdays.ToList()
                .FindIndex(w => w.Equals(token, StringComparison.OrdinalIgnoreCase) ||
                                token.StartsWith(w, StringComparison.OrdinalIgnoreCase));
            if (named >= 0)
            {
                days.Add(named);
            }
        }

        return days.Distinct().ToList();
    }

    public static ScheduleRowViewModel From(Schedule s) => new()
    {
        Target = s.Target,
        DaysText = string.Join(",", s.Days.Select(d => d is >= 0 and <= 6 ? Scheduling.Weekdays[d] : d.ToString(System.Globalization.CultureInfo.InvariantCulture))),
        Start = s.Start,
        End = s.End,
    };
}
/// <summary>Row VM for a hosts-file backup available to restore.</summary>
public sealed partial class BackupRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _fileName = string.Empty;

    [ObservableProperty]
    private string _created = string.Empty;

    [ObservableProperty]
    private long _sizeBytes;

    public string Label => $"{FileName} — {Created} ({SizeBytes / 1024.0:0.#} KB)";
}

/// <summary>One verified, non-secret full-state recovery point.</summary>
public sealed class FullStateSnapshotRowViewModel
{
    public string SnapshotId { get; init; } = string.Empty;
    public string Created { get; init; } = string.Empty;
    public string AppVersion { get; init; } = string.Empty;
    public int SchemaVersion { get; init; }
    public string Sha256 { get; init; } = string.Empty;
    public long SizeBytes { get; init; }
    public bool Verified { get; init; }
    public IReadOnlyList<string> Components { get; init; } = Array.Empty<string>();

    public string Label => I18n.T("Recovery_RowLabel", "{0} — {1} · {2:0.##} MB{3}", SnapshotId, Created,
        SizeBytes / 1024.0 / 1024.0, Verified ? I18n.T("Recovery_VerifiedSuffix", " · verified") : I18n.T("Recovery_InvalidSuffix", " · invalid"));

    public static FullStateSnapshotRowViewModel From(FullStateSnapshot snapshot) => new()
    {
        SnapshotId = snapshot.SnapshotId,
        Created = snapshot.Created,
        AppVersion = snapshot.AppVersion,
        SchemaVersion = snapshot.SchemaVersion,
        Sha256 = snapshot.Sha256,
        SizeBytes = snapshot.SizeBytes,
        Verified = snapshot.Verified,
        Components = snapshot.Components.ToArray(),
    };
}

/// <summary>Selectable adapter with its exact pre-change DNS posture.</summary>
public sealed partial class DnsAdapterRowViewModel : ObservableObject
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public bool IsVpn { get; init; }

    [ObservableProperty]
    private bool _isSelected;

    public string Posture { get; init; } = string.Empty;
    public string Label => I18n.T("DnsAdapter_RowLabel", "{0}{1} — {2}", Name,
        IsVpn ? I18n.T("DnsAdapter_VpnSuffix", " · VPN/tunnel") : string.Empty, Posture);

    public static DnsAdapterRowViewModel From(ResolverAdapterInfo adapter) => new()
    {
        Id = adapter.Id,
        Name = adapter.Name,
        Description = adapter.Description,
        IsVpn = adapter.IsVpn,
        IsSelected = adapter.IsUp && !adapter.IsVpn,
        Posture = adapter.UsesDhcp
            ? I18n.T("DnsAdapter_DhcpPosture", "DHCP · effective {0}", Join(adapter.EffectiveServers))
            : I18n.T("DnsAdapter_StaticPosture", "Static {0} · effective {1}", Join(adapter.ConfiguredServers), Join(adapter.EffectiveServers)),
    };

    private static string Join(IEnumerable<string> values)
    {
        var text = string.Join(", ", values);
        return text.Length == 0 ? I18n.T("Common_NoneLower", "none") : text;
    }
}

/// <summary>Row VM for one Windows DNS resolver-cache entry.</summary>
public sealed partial class DnsCacheEntryViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _type = string.Empty;

    [ObservableProperty]
    private int _dataLength;

    [ObservableProperty]
    private uint _flags;

    [ObservableProperty]
    private bool _serviceBinding;

    [ObservableProperty]
    private string _privacyRole = string.Empty;

    public string DataLengthText => DataLength == 0
        ? "-"
        : $"{DataLength} B";

    public string FlagsText => Flags == 0
        ? "0"
        : "0x" + Flags.ToString("X8", System.Globalization.CultureInfo.InvariantCulture);

    public static DnsCacheEntryViewModel From(DnsCacheEntry entry) => new()
    {
        Name = entry.Name,
        Type = entry.Type,
        DataLength = entry.DataLength,
        Flags = entry.Flags,
        ServiceBinding = entry.ServiceBinding,
        PrivacyRole = entry.PrivacyRole,
    };
}

/// <summary>One directly queried HTTPS/SVCB service-binding record.</summary>
public sealed class ServiceBindingRecordViewModel
{
    public string DnsType { get; init; } = string.Empty;
    public string OwnerName { get; init; } = string.Empty;
    public uint TtlSeconds { get; init; }
    public uint Priority { get; init; }
    public string Target { get; init; } = string.Empty;
    public bool AliasMode { get; init; }
    public bool EchAdvertised { get; init; }
    public bool Malformed { get; init; }
    public string Diagnostic { get; init; } = string.Empty;
    public IReadOnlyList<ServiceBindingParameter> Parameters { get; init; } = Array.Empty<ServiceBindingParameter>();

    public string ModeText => AliasMode
        ? I18n.T("ServiceBinding_AliasMode", "Alias")
        : I18n.T("ServiceBinding_ServiceMode", "Service");

    public string ParametersText => Parameters.Count == 0
        ? I18n.T("Common_NoneLower", "none")
        : string.Join("; ", Parameters.Select(static p => $"{p.Name}={p.Value}"));

    public string EchText => EchAdvertised
        ? I18n.T("ServiceBinding_EchAdvertised", "advertised")
        : I18n.T("ServiceBinding_EchNotAdvertised", "not advertised");

    public string HealthText => Malformed
        ? I18n.T("ServiceBinding_Malformed", "Malformed: {0}", Diagnostic)
        : string.IsNullOrWhiteSpace(Diagnostic)
            ? I18n.T("Health_Ok", "OK")
            : Diagnostic;

    public static ServiceBindingRecordViewModel From(ServiceBindingRecord record) => new()
    {
        DnsType = record.DnsType,
        OwnerName = record.OwnerName,
        TtlSeconds = record.TtlSeconds,
        Priority = record.Priority,
        Target = record.Target,
        AliasMode = record.AliasMode,
        EchAdvertised = record.EchAdvertised,
        Malformed = record.Malformed,
        Diagnostic = record.Diagnostic,
        Parameters = record.Parameters.ToArray(),
    };
}

/// <summary>Row VM for the AI-knowledge review panel (NET-107).</summary>
public sealed partial class KnowledgeEntryViewModel : ObservableObject
{
    [ObservableProperty]
    private string _kind = string.Empty;   // "purpose" | "category" | "connection"

    [ObservableProperty]
    private string _key = string.Empty;    // domain, or host/ip

    [ObservableProperty]
    private string _value = string.Empty;  // AI-learned label

    [ObservableProperty]
    private string _editValue = string.Empty; // editable before promoting

    [ObservableProperty]
    private string _userOverride = string.Empty; // "" until promoted/corrected

    [ObservableProperty]
    private string _created = string.Empty;

    [ObservableProperty]
    private bool _isNew;

    public string CreatedText => TimeText.Compact(Created);
}

/// <summary>Row VM for the VPN kill-switch adapter picker (NET-119).</summary>
public sealed partial class AdapterRowViewModel : ObservableObject
{
    /// <summary>The name/description substring passed to the service as the match key.</summary>
    [ObservableProperty]
    private string _match = string.Empty;

    [ObservableProperty]
    private string _label = string.Empty;
}

/// <summary>Row VM for per-app VPN adapter bindings (NET-157).</summary>
public sealed partial class AppVpnBindingRowViewModel : ObservableObject
{
    [ObservableProperty]
    private string _programPath = string.Empty;

    [ObservableProperty]
    private string _adapter = string.Empty;

    [ObservableProperty]
    private string _ruleName = string.Empty;

    [ObservableProperty]
    private bool _selectedAdapterUp;

    [ObservableProperty]
    private string _blockedInterfacesText = string.Empty;

    public string AdapterStatus => SelectedAdapterUp
        ? I18n.T("Vpn_AdapterUp", "adapter up")
        : I18n.T("Vpn_AdapterDown", "adapter down or absent");

    public static AppVpnBindingRowViewModel From(AppVpnBinding binding) => new()
    {
        ProgramPath = binding.ProgramPath,
        Adapter = binding.Adapter,
        RuleName = binding.RuleName,
        SelectedAdapterUp = binding.SelectedAdapterUp,
        BlockedInterfacesText = binding.BlockedInterfaces.Count == 0
            ? I18n.T("Vpn_NoneActive", "none active")
            : string.Join(", ", binding.BlockedInterfaces),
    };
}

/// <summary>Row VM for a one-click blockable service.</summary>
public sealed partial class BlockableServiceViewModel : ObservableObject
{
    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private bool _blocked;

    [ObservableProperty]
    private int _domainCount;

    [ObservableProperty]
    private string _note = string.Empty;

    public string Label => $"{Name} ({DomainCount})";
}
