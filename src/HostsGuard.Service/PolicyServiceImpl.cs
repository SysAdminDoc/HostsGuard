using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>
/// Policy service: the scheduled-blocking editor surface. Profiles and blocked
/// services return typed not-implemented errors until their engines land
/// (network profiles / blocked-services parity items).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class PolicyServiceImpl : Policy.PolicyBase
{
    private readonly ServiceState _state;

    public PolicyServiceImpl(ServiceState state) => _state = state;

    [GeneratedRegex("^([01][0-9]|2[0-3]):[0-5][0-9]$")]
    private static partial Regex HhMm();

    public override Task<ScheduleList> GetSchedules(Empty request, ServerCallContext context)
    {
        var list = new ScheduleList();
        foreach (var (target, days, start, end) in _state.Db.GetSchedules())
        {
            var schedule = new Schedule { Target = target, Start = start, End = end };
            foreach (var day in days.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (int.TryParse(day, out var v))
                {
                    schedule.Days.Add(v);
                }
            }

            list.Schedules.Add(schedule);
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> SetSchedules(ScheduleList request, ServerCallContext context)
    {
        foreach (var s in request.Schedules)
        {
            if (string.IsNullOrWhiteSpace(s.Target))
            {
                return Task.FromResult(Error("invalid_schedule", "schedule target is required"));
            }

            if (!HhMm().IsMatch(s.Start) || !HhMm().IsMatch(s.End))
            {
                return Task.FromResult(Error("invalid_schedule", $"'{s.Target}': start/end must be HH:mm"));
            }

            if (s.Days.Count == 0 || s.Days.Any(d => d is < 0 or > 6))
            {
                return Task.FromResult(Error("invalid_schedule", $"'{s.Target}': days must be 0 (Mon) .. 6 (Sun)"));
            }
        }

        _state.Db.SetSchedules(request.Schedules.Select(s =>
            (s.Target, string.Join(",", s.Days), s.Start, s.End)));
        _state.Schedules.Kick();
        return Task.FromResult(Ok($"saved {request.Schedules.Count} schedules"));
    }

    public override Task<ProfileList> ListProfiles(Empty request, ServerCallContext context)
        => Task.FromResult(new ProfileList());

    public override Task<Ack> SwitchProfile(ProfileRequest request, ServerCallContext context)
        => Task.FromResult(Error("not_implemented", "network profiles arrive with the profile engine"));

    public override Task<Ack> ToggleService(ServiceToggleRequest request, ServerCallContext context)
    {
        var name = (request.Service ?? string.Empty).Trim();
        var domains = BlockedServices.DomainsFor(name);
        if (domains is null)
        {
            return Task.FromResult(Error("unknown_service", $"'{name}' is not a known service"));
        }

        var source = $"service:{name}";
        if (request.Block)
        {
            var added = 0;
            var newRows = new List<(string, string, string)>();
            foreach (var d in domains)
            {
                var status = _state.Db.GetDomainStatus(d);

                // A manual whitelist wins over the one-click toggle.
                if (status == "whitelisted" && _state.Db.GetDomainSource(d) != source)
                {
                    continue;
                }

                if (_state.Hosts.Block(d))
                {
                    added++;
                }

                // Only rows this toggle creates carry the service source —
                // pre-existing manual blocks keep their identity so the revert
                // never claims them.
                if (status is null)
                {
                    newRows.Add((d, "blocked", source));
                }
            }

            _state.Db.AddDomainsBulk(newRows);
            _state.Db.LogEvent(name, "blocked", details: $"service toggle ({domains.Count} domains)", reason: "service");
            var note = name == BlockedServices.TelemetryService ? $" — {BlockedServices.TelemetryDefenderNote}" : string.Empty;
            return Task.FromResult(Ok($"blocked {name} ({added} new of {domains.Count} domains){note}"));
        }

        // Self-owned revert: only rows this toggle created are removed.
        var removed = 0;
        foreach (var row in _state.Db.GetDomains(status: "blocked", source: source))
        {
            _state.Hosts.Unblock(row.Domain);
            _state.Db.RemoveDomain(row.Domain);
            removed++;
        }

        _state.Db.LogEvent(name, "unblocked", details: $"service toggle ({removed} domains)", reason: "service");
        return Task.FromResult(Ok($"unblocked {name} ({removed} domains)"));
    }

    public override Task<ServiceStates> ListServices(Empty request, ServerCallContext context)
    {
        var states = new ServiceStates();
        foreach (var name in BlockedServices.Services.Keys.Append(BlockedServices.TelemetryService))
        {
            var source = $"service:{name}";
            var blockedCount = _state.Db.GetDomains(status: "blocked", source: source).Count;
            states.Services.Add(new BlockableService
            {
                Name = name,
                Blocked = blockedCount > 0,
                DomainCount = BlockedServices.DomainsFor(name)!.Count,
                Note = name == BlockedServices.TelemetryService ? BlockedServices.TelemetryDefenderNote : string.Empty,
            });
        }

        return Task.FromResult(states);
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}
