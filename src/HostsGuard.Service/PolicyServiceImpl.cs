using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Grpc.Core;
using HostsGuard.Contracts;
using HostsGuard.Core;
using HostsGuard.Data;

namespace HostsGuard.Service;

/// <summary>
/// Policy service: the scheduled-blocking editor surface. Profiles and blocked
/// services return typed not-implemented errors until their engines land
/// (network profiles / blocked-services parity items).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class PolicyServiceImpl : Policy.PolicyBase
{
    private const int MaxRemotePolicyBytes = 10 * 1024 * 1024;

    private readonly ServiceState _state;
    private readonly Func<DateTime> _nowUtc;

    public PolicyServiceImpl(ServiceState state) : this(state, () => state.Clock.UtcNow)
    {
    }

    internal PolicyServiceImpl(ServiceState state, Func<DateTime> nowUtc)
    {
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _nowUtc = nowUtc ?? throw new ArgumentNullException(nameof(nowUtc));
    }

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
        if (_state.GateWhenLocked("Policy") is { } gate) return Task.FromResult(gate);

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
        if (_state.GateWhenLocked("Policy") is { } gate) return Task.FromResult(gate);

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
        if (_state.GateWhenLocked("Policy") is { } gate) return Task.FromResult(gate);

        var name = (request.Name ?? string.Empty).Trim();
        if (!_state.Db.ListProfiles().Contains(name))
        {
            return Task.FromResult(Error("unknown_profile", $"profile '{name}' does not exist"));
        }

        var (target, added) = ApplyProfile(name, "profile_switched");
        return Task.FromResult(Ok($"switched to '{name}': {target} blocked domains reconciled"));
    }

    /// <summary>
    /// Reconcile the hosts file to a saved profile and mark it active. Shared by
    /// the manual switch and the network auto-switch (NET-083). Returns
    /// (blocked-count, newly-added).
    /// </summary>
    internal (int Target, int Added) ApplyProfile(string name, string logAction)
    {
        // Safety net: the pre-switch state is always recoverable.
        _state.Db.SaveProfile("(previous)");

        var rules = _state.Db.LoadProfile(name);
        _state.Db.ReplaceDomains(rules);
        var blocked = rules.Where(r => r.Status == "blocked").Select(r => r.Domain).ToList();
        var (added, target) = _state.Hosts.Reconcile(blocked);
        _state.Db.SetMeta("active_profile", name);
        _state.Db.LogEvent(name, logAction, details: $"reconciled +{added} to {target} blocked");
        return (target, added);
    }

    public override Task<Ack> DeleteProfile(ProfileRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("Policy") is { } gate) return Task.FromResult(gate);

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
        if (_state.GateWhenLocked("Policy") is { } gate) return Task.FromResult(gate);

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
    {
        var snapshot = _state.Lock.GetStatus(_nowUtc());
        return Task.FromResult(new LockState
        {
            Enabled = snapshot.Enabled,
            Unlocked = snapshot.Enabled && !snapshot.Locked,
            Degraded = snapshot.Degraded,
            FailedAttempts = snapshot.FailedAttempts,
            RetryAfterSeconds = snapshot.RetryAfterSeconds,
            Message = snapshot.Message,
        });
    }

    public override Task<Ack> SetLock(LockRequest request, ServerCallContext context)
    {
        var action = (request.Action ?? string.Empty).Trim().ToLowerInvariant();
        var result = action switch
        {
            "enable" => _state.Lock.Enable(request.Password),
            "disable" => _state.Lock.Disable(request.Password, _nowUtc()),
            _ => new SettingsLockActionResult(
                false,
                $"unknown lock action '{request.Action}' (enable|disable)",
                "lock"),
        };

        if (result.Ok)
        {
            _state.Db.LogEvent("settings", $"lock_{action}", reason: "lock");
        }

        ReportLockSecurityEvent(result);
        return Task.FromResult(result.Ok ? Ok(result.Message) : Error(result.ErrorCode, result.Message));
    }

    public override Task<Ack> Unlock(LockRequest request, ServerCallContext context)
    {
        var result = _state.Lock.Unlock(request.Password, request.Minutes, _nowUtc());
        ReportLockSecurityEvent(result);
        return Task.FromResult(result.Ok ? Ok(result.Message) : Error(result.ErrorCode, result.Message));
    }

    private void ReportLockSecurityEvent(SettingsLockActionResult result)
    {
        if (!result.ReportSecurityEvent)
        {
            return;
        }

        _state.Db.AddAlert(
            "settings_lock_security",
            "warning",
            "Repeated settings-lock password failures",
            "settings lock",
            $"Password verification was throttled after repeated failures; retry delay is bounded to {SettingsLock.MaxRetryDelay.TotalSeconds:0} seconds and no protected posture changed.",
            action: "password_failures");
        _state.Db.LogEvent(
            "settings",
            "lock_auth_throttled",
            details: "repeated password failures triggered the bounded verification throttle",
            reason: "lock");
    }

    public override Task<Ack> SetHostsProtection(HostsProtectionRequest request, ServerCallContext context)
    {
        if (!request.Enabled)
        {
            return Task.FromResult(Error("acl_relax_unsupported",
                "relaxing hosts-file write protection is not supported — the DACL stays locked to SYSTEM and Administrators for safety"));
        }

        try
        {
            Windows.HostsAcl.Harden(Windows.HostsEngine.DefaultHostsPath);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            return Task.FromResult(Error("acl", $"could not update hosts protection: {ex.Message}"));
        }

        _state.Db.LogEvent("hosts", "write_protection", details: "enabled", reason: "lock");
        return Task.FromResult(Ok("hosts file protected — only SYSTEM and Administrators can write it"));
    }

    // ─── Automatic network-profile switching (NET-083) ───────────────────────

    public override Task<CurrentNetwork> GetCurrentNetwork(Empty request, ServerCallContext context)
    {
        var net = _state.NetworkIdentity?.Current();
        return Task.FromResult(new CurrentNetwork
        {
            Fingerprint = net?.Fingerprint ?? string.Empty,
            Label = net?.Label ?? string.Empty,
            Online = net is not null,
            GatewayMac = net?.GatewayMac ?? string.Empty,
            Ssid = net?.Ssid ?? string.Empty,
            InterfaceName = net?.InterfaceName ?? string.Empty,
            DnsSuffix = net?.DnsSuffix ?? string.Empty,
            VpnPresent = net?.VpnPresent ?? false,
        });
    }

    public override Task<NetworkProfileMap> GetNetworkProfiles(Empty request, ServerCallContext context)
    {
        var map = new NetworkProfileMap();
        foreach (var (fingerprint, profile, label) in _state.Db.GetNetworkProfiles())
        {
            NetworkProfileMatchRule rule;
            try
            {
                rule = NetworkProfileSelectorCodec.Decode(fingerprint, profile, label);
            }
            catch (FormatException)
            {
                continue;
            }

            var entry = new NetworkProfileEntry
            {
                Fingerprint = rule.Fingerprint,
                Profile = rule.Profile,
                Label = rule.Label,
                GatewayMac = rule.GatewayMac,
                Ssid = rule.Ssid,
                InterfaceName = rule.InterfaceName,
                DnsSuffix = rule.DnsSuffix,
            };
            if (rule.VpnPresent.HasValue)
            {
                entry.VpnPresent = rule.VpnPresent.Value;
            }

            map.Entries.Add(entry);
        }

        return Task.FromResult(map);
    }

    public override Task<Ack> SetNetworkProfile(NetworkProfileEntry request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("Policy") is { } gate) return Task.FromResult(gate);

        var profile = (request.Profile ?? string.Empty).Trim();
        var label = (request.Label ?? string.Empty).Trim();
        var rule = new NetworkProfileMatchRule(
            profile,
            label,
            (request.Fingerprint ?? string.Empty).Trim(),
            (request.GatewayMac ?? string.Empty).Trim(),
            (request.Ssid ?? string.Empty).Trim(),
            (request.InterfaceName ?? string.Empty).Trim(),
            (request.DnsSuffix ?? string.Empty).Trim(),
            request.HasVpnPresent ? request.VpnPresent : null);
        if (rule.PredicateCount == 0)
        {
            return Task.FromResult(Error("invalid_network", "at least one network match criterion is required"));
        }

        if (profile.Length != 0 && !_state.Db.ListProfiles().Contains(profile))
        {
            return Task.FromResult(Error("unknown_profile", $"profile '{profile}' does not exist"));
        }

        _state.Db.SetNetworkProfile(NetworkProfileSelectorCodec.Encode(rule), profile, label);
        return Task.FromResult(Ok(profile.Length == 0
            ? "network→profile mapping removed"
            : $"'{label}' will auto-activate profile '{profile}'"));
    }

    // ─── Portable policy export/import (NET-089) ─────────────────────────────

    public override Task<PolicyDocument> ExportPolicy(Empty request, ServerCallContext context)
    {
        var policy = PolicyPortability.Export(_state);
        return Task.FromResult(new PolicyDocument { Json = policy.ToJson() });
    }

    public override Task<ImportPolicyResult> PreviewPolicyImport(ImportPolicyRequest request, ServerCallContext context)
    {
        var (policy, error) = ReadPortablePolicy(request.Json ?? string.Empty);
        if (error is not null)
        {
            return Task.FromResult(error);
        }

        var preview = PolicyPortability.PreviewImport(_state, policy!);
        return Task.FromResult(ToImportResult(
            ok: true,
            message: $"policy preview: +{preview.Added}, ~{preview.Changed}, -{preview.Removed}",
            summary: preview.Summary,
            preview: true,
            added: preview.Added,
            changed: preview.Changed,
            removed: preview.Removed));
    }

    public override Task<ImportPolicyResult> ImportPolicy(ImportPolicyRequest request, ServerCallContext context)
    {
        // A policy import is a broad mutation — respect the settings lock, and it
        // may also re-arm the lock from the document.
        if (_state.GateWhenLocked("Policy") is { } gate)
        {
            return Task.FromResult(new ImportPolicyResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode });
        }

        var (policy, error) = ReadPortablePolicy(request.Json ?? string.Empty);
        if (error is not null)
        {
            return Task.FromResult(error);
        }

        var preview = PolicyPortability.PreviewImport(_state, policy!);
        if (request.Preview)
        {
            return Task.FromResult(ToImportResult(
                ok: true,
                message: $"policy preview: +{preview.Added}, ~{preview.Changed}, -{preview.Removed}",
                summary: preview.Summary,
                preview: true,
                added: preview.Added,
                changed: preview.Changed,
                removed: preview.Removed));
        }

        var checkpointJson = PolicyPortability.Export(_state).ToJson();
        var checkpointId = _state.Db.CreatePolicyImportCheckpoint(checkpointJson, preview.Summary);
        var summary = PolicyPortability.Import(_state, policy!);
        return Task.FromResult(ToImportResult(
            ok: true,
            message: $"policy imported ({policy!.Domains.Count} domains); checkpoint {checkpointId}",
            summary: summary,
            added: preview.Added,
            changed: preview.Changed,
            removed: preview.Removed,
            checkpointId: checkpointId));
    }

    public override Task<ImportPolicyResult> RestorePolicyCheckpoint(Empty request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("Policy") is { } gate)
        {
            return Task.FromResult(new ImportPolicyResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode });
        }

        var checkpoint = _state.Db.GetLatestPolicyImportCheckpoint();
        if (checkpoint is null)
        {
            return Task.FromResult(new ImportPolicyResult
            {
                Ok = false,
                Message = "no policy import checkpoint is available",
                ErrorCode = "hostsguard.error.v1/no_checkpoint",
            });
        }

        var (policy, error) = ReadPortablePolicy(checkpoint.Json);
        if (error is not null)
        {
            error.Message = $"checkpoint {checkpoint.Id} could not be read: {error.Message}";
            return Task.FromResult(error);
        }

        var current = PolicyPortability.Export(_state);
        var currentPreview = PolicyPortability.PreviewImport(_state, current);
        _state.Db.CreatePolicyImportCheckpoint(current.ToJson(), currentPreview.Summary);
        var summary = PolicyPortability.Restore(_state, policy!);
        return Task.FromResult(ToImportResult(
            ok: true,
            message: $"policy checkpoint {checkpoint.Id} restored",
            summary: summary,
            checkpointId: checkpoint.Id));
    }

    public override Task<PolicySubscriptionList> ListPolicySubscriptions(Empty request, ServerCallContext context)
    {
        var list = new PolicySubscriptionList();
        foreach (var row in _state.Db.GetPolicySubscriptions())
        {
            list.Subscriptions.Add(ToPolicySubscription(row));
        }

        return Task.FromResult(list);
    }

    public override Task<Ack> SavePolicySubscription(PolicySubscriptionRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("Policy") is { } gate) return Task.FromResult(gate);

        var resolved = ResolveSubscription(request, requireExisting: false);
        if (resolved.Error is not null)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = resolved.Error.Message,
                ErrorCode = resolved.Error.ErrorCode,
            });
        }

        var id = _state.Db.SavePolicySubscription(
            resolved.Row?.Id ?? request.Id,
            resolved.Name,
            resolved.Url,
            request.Enabled,
            request.AutoApply,
            request.PinHash);
        return Task.FromResult(Ok($"policy subscription '{resolved.Name}' saved (id {id})"));
    }

    public override Task<Ack> DeletePolicySubscription(PolicySubscriptionRequest request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("Policy") is { } gate) return Task.FromResult(gate);

        var resolved = ResolveSubscription(request, requireExisting: true);
        if (resolved.Error is not null)
        {
            return Task.FromResult(new Ack
            {
                Ok = false,
                Message = resolved.Error.Message,
                ErrorCode = resolved.Error.ErrorCode,
            });
        }

        var deleted = _state.Db.DeletePolicySubscription(resolved.Row!.Id);
        return Task.FromResult(deleted
            ? Ok($"policy subscription '{resolved.Row.Name}' removed")
            : Error("unknown_policy_subscription", "policy subscription was not found"));
    }

    public override async Task<ImportPolicyResult> PreviewPolicySubscription(
        PolicySubscriptionRequest request,
        ServerCallContext context)
    {
        var fetched = await FetchSubscriptionPolicyAsync(request, context.CancellationToken);
        if (fetched.Error is not null)
        {
            return fetched.Error;
        }

        var preview = PolicyPortability.PreviewImport(_state, fetched.Policy!);
        return ToImportResult(
            ok: true,
            message: $"subscription preview: +{preview.Added}, ~{preview.Changed}, -{preview.Removed}; sha256 {fetched.Hash}",
            summary: SubscriptionSummary(fetched, preview.Summary),
            preview: true,
            added: preview.Added,
            changed: preview.Changed,
            removed: preview.Removed);
    }

    public override async Task<ImportPolicyResult> ApplyPolicySubscription(
        PolicySubscriptionRequest request,
        ServerCallContext context)
    {
        if (_state.GateWhenLocked("Policy") is { } gate)
        {
            return new ImportPolicyResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode };
        }

        return await ApplyPolicySubscriptionCoreAsync(request, context.CancellationToken);
    }

    public override async Task<ImportPolicyResult> RefreshPolicySubscriptions(Empty request, ServerCallContext context)
    {
        if (_state.GateWhenLocked("Policy") is { } gate)
        {
            return new ImportPolicyResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode };
        }

        var rows = _state.Db.GetPolicySubscriptions()
            .Where(s => s.Enabled && s.AutoApply)
            .ToList();
        if (rows.Count == 0)
        {
            return ToImportResult(
                ok: true,
                message: "no policy subscriptions have auto-apply enabled",
                summary: Array.Empty<string>());
        }

        var summary = new List<string>();
        long added = 0;
        long changed = 0;
        long removed = 0;
        var failures = 0;
        foreach (var row in rows)
        {
            var result = await ApplyPolicySubscriptionCoreAsync(new PolicySubscriptionRequest
            {
                Id = row.Id,
                Name = row.Name,
                Url = row.Url,
                Enabled = row.Enabled,
                AutoApply = row.AutoApply,
                PinHash = row.PinHash,
            }, context.CancellationToken);
            if (!result.Ok)
            {
                failures++;
                summary.Add($"{row.Name}: {result.Message}");
                continue;
            }

            added += result.Added;
            changed += result.Changed;
            removed += result.Removed;
            summary.Add($"{row.Name}: {result.Message}");
        }

        return ToImportResult(
            ok: failures == 0,
            message: failures == 0
                ? $"refreshed {rows.Count} policy subscriptions"
                : $"refreshed {rows.Count - failures} policy subscriptions; {failures} failed",
            summary: summary,
            added: added,
            changed: changed,
            removed: removed);
    }

    public override Task<ImportPolicyResult> RollbackPolicySubscription(
        PolicySubscriptionRequest request,
        ServerCallContext context)
    {
        if (_state.GateWhenLocked("Policy") is { } gate)
        {
            return Task.FromResult(new ImportPolicyResult { Ok = false, Message = gate.Message, ErrorCode = gate.ErrorCode });
        }

        var resolved = ResolveSubscription(request, requireExisting: true);
        if (resolved.Error is not null)
        {
            return Task.FromResult(resolved.Error);
        }

        var row = resolved.Row!;
        if (row.LastCheckpointId <= 0)
        {
            return Task.FromResult(new ImportPolicyResult
            {
                Ok = false,
                Message = $"policy subscription '{row.Name}' has no rollback checkpoint",
                ErrorCode = "hostsguard.error.v1/no_checkpoint",
            });
        }

        var checkpoint = _state.Db.GetPolicyImportCheckpoint(row.LastCheckpointId);
        if (checkpoint is null)
        {
            return Task.FromResult(new ImportPolicyResult
            {
                Ok = false,
                Message = $"policy subscription checkpoint {row.LastCheckpointId} was not found",
                ErrorCode = "hostsguard.error.v1/no_checkpoint",
            });
        }

        var (policy, error) = ReadPortablePolicy(checkpoint.Json);
        if (error is not null)
        {
            error.Message = $"subscription checkpoint {checkpoint.Id} could not be read: {error.Message}";
            return Task.FromResult(error);
        }

        var current = PolicyPortability.Export(_state);
        var currentPreview = PolicyPortability.PreviewImport(_state, current);
        _state.Db.CreatePolicyImportCheckpoint(current.ToJson(), currentPreview.Summary);
        var summary = PolicyPortability.Restore(_state, policy!);
        return Task.FromResult(ToImportResult(
            ok: true,
            message: $"policy subscription '{row.Name}' rolled back to checkpoint {checkpoint.Id}",
            summary: summary,
            checkpointId: checkpoint.Id));
    }

    private async Task<ImportPolicyResult> ApplyPolicySubscriptionCoreAsync(
        PolicySubscriptionRequest request,
        CancellationToken ct)
    {
        var fetched = await FetchSubscriptionPolicyAsync(request, ct);
        if (fetched.Error is not null)
        {
            var resolved = ResolveSubscription(request, requireExisting: false);
            if (resolved.Error is null)
            {
                _state.Db.RecordPolicySubscriptionFailure(
                    resolved.Row?.Id ?? request.Id,
                    resolved.Url,
                    resolved.Name,
                    fetched.Error.Message);
            }

            return fetched.Error;
        }

        var preview = PolicyPortability.PreviewImport(_state, fetched.Policy!);
        var checkpointJson = PolicyPortability.Export(_state).ToJson();
        var checkpointId = _state.Db.CreatePolicyImportCheckpoint(checkpointJson, preview.Summary);
        var summary = PolicyPortability.Import(_state, fetched.Policy!);
        var pinHash = request.PinCurrentHash
            ? fetched.Hash
            : !string.IsNullOrWhiteSpace(request.PinHash)
                ? request.PinHash
                : fetched.Row?.PinHash ?? string.Empty;
        var explicitMetadata = !string.IsNullOrWhiteSpace(request.Url) || !string.IsNullOrWhiteSpace(request.Name);
        var savedId = _state.Db.RecordPolicySubscriptionApplied(
            fetched.Row?.Id ?? request.Id,
            fetched.Name,
            fetched.Url,
            explicitMetadata ? request.Enabled : fetched.Row?.Enabled ?? request.Enabled,
            explicitMetadata ? request.AutoApply : fetched.Row?.AutoApply ?? request.AutoApply,
            pinHash,
            fetched.Hash,
            checkpointId,
            SubscriptionSummary(fetched, summary));
        return ToImportResult(
            ok: true,
            message: $"policy subscription '{fetched.Name}' applied (id {savedId}, checkpoint {checkpointId}, sha256 {fetched.Hash})",
            summary: summary,
            added: preview.Added,
            changed: preview.Changed,
            removed: preview.Removed,
            checkpointId: checkpointId);
    }

    private async Task<SubscriptionFetchResult> FetchSubscriptionPolicyAsync(
        PolicySubscriptionRequest request,
        CancellationToken ct)
    {
        var resolved = ResolveSubscription(request, requireExisting: false);
        if (resolved.Error is not null)
        {
            return new SubscriptionFetchResult(null, null, string.Empty, string.Empty, string.Empty, resolved.Error);
        }

        if (_state.ListFetcher is null)
        {
            return new SubscriptionFetchResult(null, null, resolved.Name, resolved.Url, string.Empty, new ImportPolicyResult
            {
                Ok = false,
                Message = "remote policy subscriptions are unavailable because no list fetcher is configured",
                ErrorCode = "hostsguard.error.v1/no_fetcher",
            });
        }

        try
        {
            var json = await _state.ListFetcher.FetchAsync(resolved.Url, MaxRemotePolicyBytes, ct);
            var hash = Sha256(json);
            var pinned = !string.IsNullOrWhiteSpace(request.PinHash)
                ? request.PinHash.Trim().ToLowerInvariant()
                : resolved.Row?.PinHash ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(pinned) && !hash.Equals(pinned, StringComparison.OrdinalIgnoreCase))
            {
                return new SubscriptionFetchResult(null, resolved.Row, resolved.Name, resolved.Url, hash, new ImportPolicyResult
                {
                    Ok = false,
                    Message = $"policy subscription '{resolved.Name}' hash mismatch: expected {pinned}, got {hash}",
                    ErrorCode = "hostsguard.error.v1/policy_subscription_pin_mismatch",
                });
            }

            var (policy, error) = ReadPortablePolicy(json);
            return error is not null
                ? new SubscriptionFetchResult(null, resolved.Row, resolved.Name, resolved.Url, hash, error)
                : new SubscriptionFetchResult(policy, resolved.Row, resolved.Name, resolved.Url, hash, null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new SubscriptionFetchResult(null, resolved.Row, resolved.Name, resolved.Url, string.Empty, new ImportPolicyResult
            {
                Ok = false,
                Message = $"could not fetch policy subscription '{resolved.Name}': {ex.Message}",
                ErrorCode = "hostsguard.error.v1/policy_subscription_fetch_failed",
            });
        }
    }

    private SubscriptionResolveResult ResolveSubscription(PolicySubscriptionRequest request, bool requireExisting)
    {
        var row = request.Id > 0
            ? _state.Db.GetPolicySubscription(request.Id)
            : !string.IsNullOrWhiteSpace(request.Url)
                ? _state.Db.GetPolicySubscriptionByUrl(request.Url.Trim())
                : null;
        if (requireExisting && row is null)
        {
            return new SubscriptionResolveResult(null, string.Empty, string.Empty, new ImportPolicyResult
            {
                Ok = false,
                Message = "policy subscription was not found",
                ErrorCode = "hostsguard.error.v1/unknown_policy_subscription",
            });
        }

        var requestUrl = (request.Url ?? string.Empty).Trim();
        var url = requestUrl.Length != 0 ? requestUrl : row?.Url ?? string.Empty;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return new SubscriptionResolveResult(row, string.Empty, url, new ImportPolicyResult
            {
                Ok = false,
                Message = "policy subscription URL must be absolute HTTPS",
                ErrorCode = "hostsguard.error.v1/invalid_policy_subscription_url",
            });
        }

        var requestName = (request.Name ?? string.Empty).Trim();
        var name = requestName.Length != 0 ? requestName : row?.Name ?? string.Empty;
        if (name.Length == 0)
        {
            name = DefaultSubscriptionName(uri);
        }

        return new SubscriptionResolveResult(row, name, url, null);
    }

    private static string DefaultSubscriptionName(Uri uri)
    {
        var path = uri.AbsolutePath.Trim('/');
        return path.Length == 0
            ? uri.Host
            : $"{uri.Host}/{path.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault()}";
    }

    private static IEnumerable<string> SubscriptionSummary(SubscriptionFetchResult fetched, IEnumerable<string> summary)
    {
        yield return $"subscription: {fetched.Name} ({fetched.Url})";
        yield return $"sha256: {fetched.Hash}";
        foreach (var item in summary)
        {
            yield return item;
        }
    }

    private static PolicySubscription ToPolicySubscription(PolicySubscriptionRow row) => new()
    {
        Id = row.Id,
        Name = row.Name,
        Url = row.Url,
        Enabled = row.Enabled,
        AutoApply = row.AutoApply,
        PinHash = row.PinHash,
        LastHash = row.LastHash,
        LastCheckpointId = row.LastCheckpointId,
        LastAppliedAt = row.LastAppliedAt,
        LastPreviewSummary = row.LastPreviewSummary,
        LastError = row.LastError,
        LastErrorAt = row.LastErrorAt,
        Created = row.Created,
        Updated = row.Updated,
    };

    private static string Sha256(string text)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    private sealed record SubscriptionResolveResult(
        PolicySubscriptionRow? Row,
        string Name,
        string Url,
        ImportPolicyResult? Error);

    private sealed record SubscriptionFetchResult(
        Core.PortablePolicy? Policy,
        PolicySubscriptionRow? Row,
        string Name,
        string Url,
        string Hash,
        ImportPolicyResult? Error);

    private static Ack Ok(string message) => new() { Ok = true, Message = message };

    private static Ack Error(string code, string message) =>
        new() { Ok = false, Message = message, ErrorCode = $"hostsguard.error.v1/{code}" };

    private static (Core.PortablePolicy? Policy, ImportPolicyResult? Error) ReadPortablePolicy(string json)
    {
        try
        {
            return (Core.PortablePolicy.FromJson(json), null);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or InvalidOperationException or ArgumentException)
        {
            return (null, new ImportPolicyResult
            {
                Ok = false,
                Message = $"could not read the policy document: {ex.Message}",
                ErrorCode = "hostsguard.error.v1/invalid_policy",
            });
        }
    }

    private static ImportPolicyResult ToImportResult(
        bool ok,
        string message,
        IEnumerable<string> summary,
        bool preview = false,
        long added = 0,
        long changed = 0,
        long removed = 0,
        long checkpointId = 0) => new()
        {
            Ok = ok,
            Message = message,
            Preview = preview,
            Added = added,
            Changed = changed,
            Removed = removed,
            CheckpointId = checkpointId,
            Summary = { summary },
        };
}
