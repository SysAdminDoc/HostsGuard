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

    public string AdapterStatus => SelectedAdapterUp ? "adapter up" : "adapter down or absent";

    public static AppVpnBindingRowViewModel From(AppVpnBinding binding) => new()
    {
        ProgramPath = binding.ProgramPath,
        Adapter = binding.Adapter,
        RuleName = binding.RuleName,
        SelectedAdapterUp = binding.SelectedAdapterUp,
        BlockedInterfacesText = binding.BlockedInterfaces.Count == 0
            ? "none active"
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
