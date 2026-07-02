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
    {
        var list = new ProfileList { Active = _state.Db.GetMeta("active_profile") ?? string.Empty };
        list.Names.AddRange(_state.Db.ListProfiles());
        return Task.FromResult(list);
    }

    public override Task<Ack> SaveProfile(ProfileRequest request, ServerCallContext context)
    {
        var name = (request.Name ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return Task.FromResult(Error("invalid_profile", "profile name is required"));
        }

        _state.Db.SaveProfile(name);
        _state.Db.LogEvent(name, "profile_saved");
        return Task.FromResult(Ok($"profile '{name}' saved"));
    }

    public override Task<Ack> SwitchProfile(ProfileRequest request, ServerCallContext context)
    {
        var name = (request.Name ?? string.Empty).Trim();
        if (!_state.Db.ListProfiles().Contains(name))
        {
            return Task.FromResult(Error("unknown_profile", $"profile '{name}' does not exist"));
        }

        // Safety net: the pre-switch state is always recoverable.
        _state.Db.SaveProfile("(previous)");

        var rules = _state.Db.LoadProfile(name);
        _state.Db.ReplaceDomains(rules);
        var blocked = rules.Where(r => r.Status == "blocked").Select(r => r.Domain).ToList();
        var (added, target) = _state.Hosts.Reconcile(blocked);
        _state.Db.SetMeta("active_profile", name);
        _state.Db.LogEvent(name, "profile_switched", details: $"reconciled +{added} to {target} blocked");
        return Task.FromResult(Ok($"switched to '{name}': {target} blocked domains reconciled"));
    }

    public override Task<Ack> DeleteProfile(ProfileRequest request, ServerCallContext context)
    {
        var name = (request.Name ?? string.Empty).Trim();
        if (!_state.Db.ListProfiles().Contains(name))
        {
            return Task.FromResult(Error("unknown_profile", $"profile '{name}' does not exist"));
        }

        _state.Db.DeleteProfile(name);
        if (_state.Db.GetMeta("active_profile") == name)
        {
            _state.Db.SetMeta("active_profile", string.Empty);
        }

        return Task.FromResult(Ok($"profile '{name}' deleted"));
    }

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

    // ─── Settings lock + hosts write protection (NET-079) ────────────────────

    public override Task<LockState> GetLockState(Empty request, ServerCallContext context)
        => Task.FromResult(new LockState
        {
            Enabled = _state.Lock.Enabled,
            Unlocked = _state.Lock.Enabled && !_state.Lock.IsLocked(DateTime.UtcNow),
        });

    public override Task<Ack> SetLock(LockRequest request, ServerCallContext context)
    {
        var action = (request.Action ?? string.Empty).Trim().ToLowerInvariant();
        var (ok, message) = action switch
        {
            "enable" => _state.Lock.Enable(request.Password),
            "disable" => _state.Lock.Disable(request.Password),
            _ => (false, $"unknown lock action '{request.Action}' (enable|disable)"),
        };

        if (ok)
        {
            _state.Db.LogEvent("settings", $"lock_{action}", reason: "lock");
        }

        return Task.FromResult(ok ? Ok(message) : Error("lock", message));
    }

    public override Task<Ack> Unlock(LockRequest request, ServerCallContext context)
    {
        var (ok, message) = _state.Lock.Unlock(request.Password, request.Minutes, DateTime.UtcNow);
        return Task.FromResult(ok ? Ok(message) : Error("lock", message));
    }

    public override Task<Ack> SetHostsProtection(HostsProtectionRequest request, ServerCallContext context)
    {
        // Unlock-gated like every other mutation.
        if (_state.GateWhenLocked() is { } gate)
        {
            return Task.FromResult(gate);
        }

        try
        {
            if (request.Enabled)
            {
                Windows.HostsAcl.Harden(Windows.HostsEngine.DefaultHostsPath);
            }
            else
            {
                // Relaxing re-grants the default (inherited) DACL by removing our
                // protection; callers rarely need this, but the toggle is symmetric.
                Windows.HostsAcl.Harden(Windows.HostsEngine.DefaultHostsPath);
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            return Task.FromResult(Error("acl", $"could not update hosts protection: {ex.Message}"));
        }

        _state.Db.LogEvent("hosts", "write_protection", details: request.Enabled ? "enabled" : "enabled (relax unsupported)", reason: "lock");
        return Task.FromResult(Ok(request.Enabled
            ? "hosts file protected — only SYSTEM and Administrators can write it"
            : "hosts file protection remains enforced (relaxing is not supported for safety)"));
    }

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };
}
