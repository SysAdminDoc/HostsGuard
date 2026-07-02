using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Grpc.Core;
using HostsGuard.Contracts;

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
        => Task.FromResult(Error("not_implemented", "blocked-services toggles arrive with the services engine"));

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}
