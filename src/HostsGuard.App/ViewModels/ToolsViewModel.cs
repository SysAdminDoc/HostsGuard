using System.Collections.ObjectModel;
using System.Runtime.Versioning;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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

/// <summary>
/// Tools tab: DNS flush + resolver switching, scheduled-blocking editor,
/// hosts backup, ACL hardening, redacted support-bundle export, and a domain
/// inspector. Every action round-trips the service and surfaces the typed ack.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class ToolsViewModel : ObservableObject
{
    public static readonly IReadOnlyList<(string Name, string[] Servers)> ResolverPresets = new[]
    {
        ("DHCP (default)", Array.Empty<string>()),
        ("Cloudflare (1.1.1.1)", new[] { "1.1.1.1", "1.0.0.1" }),
        ("Google (8.8.8.8)", new[] { "8.8.8.8", "8.8.4.4" }),
        ("Quad9 (9.9.9.9)", new[] { "9.9.9.9", "149.112.112.112" }),
    };

    private readonly HostsServiceClient _client;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private string _selectedResolver = "DHCP (default)";

    [ObservableProperty]
    private string _inspectDomain = string.Empty;

    [ObservableProperty]
    private string _inspectResult = string.Empty;

    public ToolsViewModel(HostsServiceClient client)
        => _client = client ?? throw new ArgumentNullException(nameof(client));

    public ObservableCollection<ScheduleRowViewModel> Schedules { get; } = new();

    public static IReadOnlyList<string> ResolverNames { get; } = ResolverPresets.Select(p => p.Name).ToList();

    [RelayCommand]
    public async Task FlushDnsAsync()
    {
        var ack = await _client.Dns.FlushCacheAsync(new Empty());
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task ApplyResolverAsync()
    {
        var preset = ResolverPresets.FirstOrDefault(p => p.Name == SelectedResolver);
        var request = new ResolverRequest();
        request.Servers.AddRange(preset.Servers ?? Array.Empty<string>());
        var ack = await _client.Dns.SetResolverAsync(request);
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task BackupHostsAsync()
    {
        var ack = await _client.Hosts.BackupHostsAsync(new Empty());
        StatusText = ack.Ok ? $"Backup written: {ack.Message}" : ack.Message;
    }

    [RelayCommand]
    public async Task HardenAclAsync()
    {
        var ack = await _client.Hosts.HardenAclAsync(new Empty());
        StatusText = ack.Message;
    }

    [RelayCommand]
    public async Task ExportBundleAsync()
    {
        var ack = await _client.Diagnostics.ExportSupportBundleAsync(new Empty());
        StatusText = ack.Ok ? $"Support bundle: {ack.Message}" : ack.Message;
    }

    [RelayCommand]
    public async Task InspectAsync()
    {
        var result = await _client.Dns.InspectAsync(new DomainRequest { Domain = InspectDomain });
        var records = result.Records.Count == 0
            ? "no records"
            : string.Join("; ", result.Records.Select(r => $"{r.Type} {r.Value}"));
        InspectResult = $"{(result.Blocked ? "BLOCKED" : "reachable")} — {records} ({result.LatencyMs} ms)";
    }

    // ─── Scheduled blocking ───────────────────────────────────────────────────

    [RelayCommand]
    public async Task LoadSchedulesAsync()
    {
        var list = await _client.Policy.GetSchedulesAsync(new Empty());
        Schedules.Clear();
        foreach (var s in list.Schedules)
        {
            Schedules.Add(ScheduleRowViewModel.From(s));
        }

        StatusText = $"{Schedules.Count} schedules";
    }

    [RelayCommand]
    public void AddSchedule() => Schedules.Add(new ScheduleRowViewModel { DaysText = "Mon,Tue,Wed,Thu,Fri" });

    [RelayCommand]
    public void RemoveSchedule(ScheduleRowViewModel row) => Schedules.Remove(row);

    [RelayCommand]
    public async Task SaveSchedulesAsync()
    {
        var list = new ScheduleList();
        foreach (var row in Schedules)
        {
            var schedule = new Schedule { Target = row.Target.Trim(), Start = row.Start.Trim(), End = row.End.Trim() };
            schedule.Days.AddRange(row.ParseDays());
            list.Schedules.Add(schedule);
        }

        var ack = await _client.Policy.SetSchedulesAsync(list);
        StatusText = ack.Message;
        if (ack.Ok)
        {
            await LoadSchedulesAsync();
        }
    }
}
