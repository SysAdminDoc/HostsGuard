using System.Reflection;
using System.Runtime.Versioning;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.Service;

/// <summary>
/// Builds and applies the NET-089 portable-policy snapshot. Kept out of the gRPC
/// impl so the whole export→import round-trip is unit-testable against a
/// <see cref="ServiceState"/> built on fakes.
/// </summary>
[SupportedOSPlatform("windows")]
public static class PolicyPortability
{
    public sealed record PolicyImportPreview(IReadOnlyList<string> Summary, long Added, long Changed, long Removed);

    /// <summary>Snapshot the machine's whole policy into a portable document.</summary>
    public static PortablePolicy Export(ServiceState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var policy = new PortablePolicy
        {
            App = AppVersion(),
            Exported = DateTime.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture),
        };

        foreach (var d in state.Db.GetDomains())
        {
            policy.Domains.Add(new PolicyDomain
            {
                Domain = d.Domain,
                Status = d.Status,
                Source = d.Source ?? string.Empty,
                Reason = d.Reason ?? string.Empty,
                Category = d.Category ?? string.Empty,
                Notes = d.Notes ?? string.Empty,
            });
        }

        // Only HostsGuard-authored rules travel; system rules stay on their host.
        // Drifted (tracked-but-missing) rows are skipped — nothing to recreate.
        if (state.Firewall is { } fw)
        {
            foreach (var r in fw.ListRules()
                .Where(r => r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal)
                    && !r.Name.StartsWith("HG_Domain_", StringComparison.Ordinal)
                    && !r.Name.StartsWith("HG_VPNBind_", StringComparison.Ordinal)))
            {
                policy.FirewallRules.Add(new PolicyFirewallRule
                {
                    Name = r.Name,
                    Direction = r.Direction,
                    Action = r.Action,
                    Enabled = r.Enabled,
                    RemoteAddr = r.RemoteAddr,
                    Protocol = r.Protocol,
                    Program = r.Program,
                    PackageFamilyName = r.PackageFamilyName,
                    PackageSid = r.PackageSid,
                    PackageDisplayName = r.PackageDisplayName,
                    PackageFullName = r.PackageFullName,
                    PackageBinaries = r.PackageBinaries,
                    RemotePorts = r.RemotePorts,
                    LocalPorts = r.LocalPorts,
                    ServiceName = r.ServiceName,
                    Interfaces = r.Interfaces,
                });
            }
        }

        foreach (var r in state.Db.ListDomainFirewallRules())
        {
            policy.DomainFirewallRules.Add(new PolicyDomainFirewallRule
            {
                Domain = r.Domain,
                Program = r.Program,
                RuleName = r.RuleName,
                Action = r.Action,
                Enabled = r.Enabled,
                RemoteAddr = r.RemoteAddr,
            });
        }

        foreach (var (target, days, start, end) in state.Db.GetSchedules())
        {
            policy.Schedules.Add(new PolicySchedule { Target = target, Days = days, Start = start, End = end });
        }

        foreach (var name in state.Db.ListProfiles())
        {
            var profile = new PolicyProfile { Name = name };
            foreach (var (domain, status, source) in state.Db.LoadProfile(name))
            {
                profile.Rules.Add(new PolicyProfileRule { Domain = domain, Status = status, Source = source ?? string.Empty });
            }

            policy.Profiles.Add(profile);
        }

        var (lockEnabled, lockHash) = state.Lock.ExportState();
        policy.Lock = new PolicyLock { Enabled = lockEnabled, Hash = lockHash };

        foreach (var (fingerprint, profile, label) in state.Db.GetNetworkProfiles())
        {
            policy.NetworkProfiles.Add(new PolicyNetworkProfile { Fingerprint = fingerprint, Profile = profile, Label = label });
        }

        foreach (var byGroup in state.Db.GetRuleGroups().GroupBy(g => g.Group, StringComparer.Ordinal))
        {
            policy.RuleGroups.Add(new PolicyRuleGroup { Name = byGroup.Key, Rules = byGroup.Select(g => g.RuleName).ToList() });
        }

        foreach (var sub in state.Db.GetBlocklistSubs())
        {
            policy.BlocklistSubs.Add(new PolicyBlocklistSub { Name = sub.Name, Url = sub.Url });
        }

        foreach (var source in state.Db.GetIpBlocklistSources())
        {
            policy.IpBlocklists.Add(new PolicyIpBlocklist { Name = source.Name, Url = source.Url, Enabled = source.Enabled });
        }

        policy.AllowlistSubs.AddRange(state.Db.GetAllowlistSubs());

        policy.Consent = new PolicyConsent
        {
            Mode = state.Consent.Mode,
            ChildInherit = state.Consent.ChildInherit,
            InboundConsent = state.Consent.InboundConsent,
            TrustedPublishers = state.Consent.TrustedPublishers.ToList(),
            TrustedFolders = state.Consent.TrustedFolders.ToList(),
        };

        var doh = state.Doh.Load();
        policy.DnsPrivacy = new PolicyDnsPrivacy
        {
            DohBlocking = state.Firewall?.RuleExists("HG_DoT_TCP") ?? false,
            QuicBlocked = state.Firewall?.RuleExists(FirewallControlServiceImpl.QuicRuleName) ?? false,
            CnameCloak = state.CnameCloak.Enabled,
            SniCapture = (state.Sni?.Active ?? false) || state.Db.GetMeta("sni_capture") == "on",
            DohIntelligence = new PolicyDohState
            {
                Updated = doh.Updated,
                Source = doh.Source,
                Sha256 = doh.Sha256,
                Ips = doh.Ips.ToList(),
            },
        };

        if (state.KillSwitch is { } killSwitch)
        {
            policy.KillSwitch = new PolicyKillSwitch
            {
                Enabled = killSwitch.Enabled,
                Adapter = killSwitch.Adapter,
            };
        }

        foreach (var binding in state.Db.ListAppVpnBindings())
        {
            policy.AppVpnBindings.Add(new PolicyAppVpnBinding
            {
                Program = binding.Program,
                Adapter = binding.Adapter,
            });
        }

        policy.UsageQuotas = state.Db.GetUsageQuotaRules()
            .Select(r => new PolicyUsageQuota
            {
                Scope = r.Scope,
                Match = r.Match,
                LimitBytes = r.LimitBytes,
                WindowDays = r.WindowDays,
                Enabled = r.Enabled,
            })
            .ToList();

        policy.LanAttackSurface = new PolicyLanAttackSurface
        {
            Toggles = state.LanAttackSurface.List()
                .Select(t => new PolicyLanAttackSurfaceToggle { Key = t.Key, Blocked = t.Blocked })
                .ToList(),
        };

        var ai = state.Ai.Settings;
        policy.Ai = new PolicyAiSettings
        {
            Model = ai.Model,
            Endpoint = ai.Endpoint,
            Enabled = ai.Enabled,
            ApiKeyConfigured = ai.ApiKey.Length != 0,
            LastRun = state.Db.GetMeta("ai_last_run"),
            LastResult = state.Db.GetMeta("ai_last_result"),
            LastReviewed = state.Db.GetMeta("ai_knowledge_reviewed_at"),
        };
        policy.AiKnowledge = state.Db.GetAllAiKnowledge()
            .Select(k => new PolicyAiKnowledge
            {
                Kind = k.Kind,
                Key = k.Key,
                Value = k.Value,
                Model = k.Model,
                Created = k.Created,
            })
            .ToList();
        policy.UserOverrides = state.Db.GetAllUserOverrides()
            .Select(o => new PolicyUserOverride
            {
                Kind = o.Kind,
                Key = o.Key,
                Value = o.Value,
                Created = o.Created,
            })
            .ToList();

        policy.Webhooks = new PolicyWebhooks
        {
            Urls = state.Webhooks.Urls.ToList(),
            SecretConfigured = state.Webhooks.Secret.Length != 0,
        };

        // Carry the handful of meta settings a portable policy should reconstruct.
        foreach (var key in PortableMetaKeys)
        {
            var value = state.Db.GetMeta(key);
            if (!string.IsNullOrEmpty(value))
            {
                policy.Settings[key] = value;
            }
        }

        return policy;
    }

    /// <summary>Meta keys carried in a portable policy (reconstructable settings).</summary>
    private static readonly string[] PortableMetaKeys = { "active_profile", "history_retention_days", "flow_teardown_enabled" };

    public static PolicyImportPreview PreviewImport(ServiceState state, PortablePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(policy);
        var summary = new List<string>();
        long added = 0;
        long changed = 0;
        long removed = 0;

        var currentDomains = state.Db.GetDomains()
            .ToDictionary(d => d.Domain, StringComparer.Ordinal);
        var desiredDomains = policy.Domains
            .Where(d => !string.IsNullOrWhiteSpace(d.Domain))
            .GroupBy(d => d.Domain.ToLowerInvariant(), StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);
        var domainAdded = desiredDomains.Keys.Count(d => !currentDomains.ContainsKey(d));
        var domainChanged = desiredDomains.Count(kv =>
            currentDomains.TryGetValue(kv.Key, out var current) &&
            (!string.Equals(current.Status, kv.Value.Status, StringComparison.Ordinal) ||
             !string.Equals(current.Source ?? string.Empty, kv.Value.Source ?? string.Empty, StringComparison.Ordinal) ||
             !string.Equals(current.Reason ?? string.Empty, kv.Value.Reason ?? string.Empty, StringComparison.Ordinal) ||
             !string.Equals(current.Category ?? string.Empty, kv.Value.Category ?? string.Empty, StringComparison.Ordinal) ||
             !string.Equals(current.Notes ?? string.Empty, kv.Value.Notes ?? string.Empty, StringComparison.Ordinal)));
        added += domainAdded;
        changed += domainChanged;
        summary.Add($"domains: +{domainAdded}, ~{domainChanged}, -0 (merge)");

        if (state.Firewall is { } fw)
        {
            var currentRules = fw.ListRules().Where(r => r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
                .ToDictionary(r => r.Name, StringComparer.Ordinal);
            var desiredRules = policy.FirewallRules.Where(r => !string.IsNullOrWhiteSpace(r.Name))
                .GroupBy(r => r.Name, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);
            var ruleAdded = desiredRules.Keys.Count(r => !currentRules.ContainsKey(r));
            var ruleChanged = desiredRules.Count(kv =>
                currentRules.TryGetValue(kv.Key, out var current) &&
                (!string.Equals(current.Action, FwRuleMapper.MapAction(kv.Value.Action), StringComparison.Ordinal) ||
                 current.Enabled != kv.Value.Enabled ||
                 !string.Equals(current.RemoteAddr, string.IsNullOrWhiteSpace(kv.Value.RemoteAddr) ? "Any" : kv.Value.RemoteAddr, StringComparison.Ordinal) ||
                 !string.Equals(current.Program, kv.Value.Program ?? string.Empty, StringComparison.Ordinal) ||
                 !string.Equals(current.PackageFamilyName, kv.Value.PackageFamilyName ?? string.Empty, StringComparison.Ordinal) ||
                 !string.Equals(current.PackageSid, kv.Value.PackageSid ?? string.Empty, StringComparison.Ordinal)));
            added += ruleAdded;
            changed += ruleChanged;
            summary.Add($"firewall rules: +{ruleAdded}, ~{ruleChanged}, -0 (merge)");
        }
        else if (policy.FirewallRules.Count != 0)
        {
            summary.Add($"firewall rules: {policy.FirewallRules.Count} skipped (engine unavailable)");
        }

        var currentSchedules = state.Db.GetSchedules()
            .Select(s => $"{s.Target}|{s.Days}|{s.Start}|{s.End}")
            .ToHashSet(StringComparer.Ordinal);
        var desiredSchedules = policy.Schedules
            .Select(s => $"{s.Target}|{s.Days}|{s.Start}|{s.End}")
            .ToHashSet(StringComparer.Ordinal);
        AddSetDiff("schedules", currentSchedules, desiredSchedules, summary, ref added, ref removed);

        var currentProfiles = state.Db.ListProfiles().ToHashSet(StringComparer.Ordinal);
        var desiredProfiles = policy.Profiles.Select(p => p.Name).Where(n => !string.IsNullOrWhiteSpace(n)).ToHashSet(StringComparer.Ordinal);
        AddSetDiff("profiles", currentProfiles, desiredProfiles, summary, ref added, ref removed, removeMissing: false);

        var currentBlocklists = state.Db.GetBlocklistSubs().Select(s => s.Name).ToHashSet(StringComparer.Ordinal);
        var desiredBlocklists = policy.BlocklistSubs.Select(s => s.Name).Where(n => !string.IsNullOrWhiteSpace(n)).ToHashSet(StringComparer.Ordinal);
        AddSetDiff("blocklist subscriptions", currentBlocklists, desiredBlocklists, summary, ref added, ref removed, removeMissing: false);

        var currentIpBlocklists = state.Db.GetIpBlocklistSources().Select(s => s.Name).ToHashSet(StringComparer.Ordinal);
        var desiredIpBlocklists = policy.IpBlocklists.Select(s => s.Name).Where(n => !string.IsNullOrWhiteSpace(n)).ToHashSet(StringComparer.Ordinal);
        AddSetDiff("IP blocklists", currentIpBlocklists, desiredIpBlocklists, summary, ref added, ref removed, removeMissing: false);

        var currentAllow = state.Db.GetAllowlistSubs().ToHashSet(StringComparer.Ordinal);
        var desiredAllow = policy.AllowlistSubs.Where(u => !string.IsNullOrWhiteSpace(u)).ToHashSet(StringComparer.Ordinal);
        AddSetDiff("allowlist subscriptions", currentAllow, desiredAllow, summary, ref added, ref removed);

        var currentNetworks = state.Db.GetNetworkProfiles().Select(n => n.Fingerprint).ToHashSet(StringComparer.Ordinal);
        var desiredNetworks = policy.NetworkProfiles.Select(n => n.Fingerprint).Where(n => !string.IsNullOrWhiteSpace(n)).ToHashSet(StringComparer.Ordinal);
        AddSetDiff("network profiles", currentNetworks, desiredNetworks, summary, ref added, ref removed, removeMissing: false);

        var currentGroups = state.Db.GetRuleGroups().Select(g => g.Group).ToHashSet(StringComparer.Ordinal);
        var desiredGroups = policy.RuleGroups.Select(g => g.Name).Where(n => !string.IsNullOrWhiteSpace(n)).ToHashSet(StringComparer.Ordinal);
        AddSetDiff("rule groups", currentGroups, desiredGroups, summary, ref added, ref removed, removeMissing: false);

        if (policy.UsageQuotas is { } quotas)
        {
            var currentQuotas = state.Db.GetUsageQuotaRules()
                .ToDictionary(q => $"{q.Scope}|{q.Match}", StringComparer.Ordinal);
            var desiredQuotas = quotas
                .Where(q => !string.IsNullOrWhiteSpace(q.Scope) && !string.IsNullOrWhiteSpace(q.Match))
                .GroupBy(q => $"{q.Scope.Trim().ToLowerInvariant()}|{q.Match.Trim()}", StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.Last(), StringComparer.Ordinal);
            var quotaAdded = desiredQuotas.Keys.Count(q => !currentQuotas.ContainsKey(q));
            var quotaChanged = desiredQuotas.Count(kv =>
                currentQuotas.TryGetValue(kv.Key, out var current) &&
                (current.LimitBytes != kv.Value.LimitBytes ||
                 current.WindowDays != kv.Value.WindowDays ||
                 current.Enabled != kv.Value.Enabled));
            var quotaRemoved = currentQuotas.Keys.Count(q => !desiredQuotas.ContainsKey(q));
            added += quotaAdded;
            changed += quotaChanged;
            removed += quotaRemoved;
            summary.Add($"usage quotas: +{quotaAdded}, ~{quotaChanged}, -{quotaRemoved}");
        }

        var postureChanged =
            policy.Lock is not null ||
            policy.Consent is not null ||
            policy.DnsPrivacy is not null ||
            policy.KillSwitch is not null ||
            policy.AppVpnBindings.Count != 0 ||
            policy.UsageQuotas is { Count: > 0 } ||
            policy.LanAttackSurface is not null ||
            policy.Ai is not null ||
            policy.Webhooks is not null;
        if (postureChanged)
        {
            changed++;
            summary.Add("posture/settings: ~1");
        }

        return new PolicyImportPreview(summary, added, changed, removed);
    }

    /// <summary>
    /// Apply an imported policy, reconstructing every section. Idempotent: applying
    /// the same document twice yields the same machine state. Returns a
    /// human-readable per-section summary.
    /// </summary>
    public static IReadOnlyList<string> Import(ServiceState state, PortablePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(policy);
        var summary = new List<string>();

        // ── Managed domains → reconcile the hosts file to the imported set ──
        foreach (var d in policy.Domains)
        {
            if (string.IsNullOrWhiteSpace(d.Domain))
            {
                continue;
            }

            state.Db.AddDomain(d.Domain, d.Status, d.Source ?? string.Empty, d.Category ?? string.Empty, d.Reason);
            if (!string.IsNullOrEmpty(d.Notes))
            {
                state.Db.SetNotes(d.Domain, d.Notes);
            }
        }

        var blocked = state.Db.GetDomains(status: "blocked").Select(r => r.Domain).ToList();
        var (added, target) = state.Hosts.Reconcile(blocked);
        summary.Add($"{policy.Domains.Count} domains ({target} blocked, +{added} new to hosts)");

        // ── HG_ firewall rules ──
        var rulesCreated = 0;
        if (state.Firewall is { } fw)
        {
            foreach (var r in policy.FirewallRules)
            {
                if (string.IsNullOrWhiteSpace(r.Name) ||
                    !r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                var rule = ToFirewallRule(r);
                if (fw.CreateRule(rule))
                {
                    rulesCreated++;
                }

                // Track even pre-existing rules so drift detection stays accurate.
                state.Db.UpsertFwState(
                    rule.Name,
                    rule.Direction,
                    rule.Action,
                    rule.RemoteAddr,
                    rule.Protocol,
                    rule.Program,
                    rule.RemotePorts,
                    rule.LocalPorts,
                    rule.ServiceName,
                    rule.Interfaces,
                    rule.PackageFamilyName,
                    rule.PackageSid,
                    rule.PackageDisplayName,
                    rule.PackageFullName,
                    rule.PackageBinaries);
                if (rule.Program.Length != 0)
                {
                    state.Identity?.Remember(rule.Name, rule.Program);
                }
            }

            summary.Add($"{policy.FirewallRules.Count} firewall rules (+{rulesCreated} created)");
        }
        else if (policy.FirewallRules.Count != 0)
        {
            summary.Add($"{policy.FirewallRules.Count} firewall rules skipped (firewall engine unavailable)");
        }

        // ── Schedules (replace-all) ──
        var domainFirewallCreated = 0;
        foreach (var r in policy.DomainFirewallRules)
        {
            if (string.IsNullOrWhiteSpace(r.Domain) ||
                string.IsNullOrWhiteSpace(r.RuleName) ||
                !r.RuleName.StartsWith("HG_Domain_", StringComparison.Ordinal))
            {
                continue;
            }

            var ruleName = r.RuleName.Trim();
            var action = FwRuleMapper.MapAction(r.Action);
            var remote = string.IsNullOrWhiteSpace(r.RemoteAddr) ? string.Empty : r.RemoteAddr.Trim();
            state.Db.UpsertDomainFirewallRule(
                r.Domain.Trim(),
                r.Program ?? string.Empty,
                ruleName,
                action,
                r.Enabled,
                remote);

            if (state.Firewall is { } fw2 && remote.Length != 0)
            {
                var rule = new FwRule(
                    ruleName,
                    "Out",
                    action,
                    r.Enabled,
                    remote,
                    "Any",
                    r.Program ?? string.Empty,
                    "hostsguard");
                if (fw2.CreateRule(rule))
                {
                    domainFirewallCreated++;
                }

                state.Db.UpsertFwState(rule.Name, rule.Direction, rule.Action, rule.RemoteAddr, rule.Protocol, rule.Program);
            }
        }

        if (policy.DomainFirewallRules.Count != 0)
        {
            summary.Add($"{policy.DomainFirewallRules.Count} domain firewall rules (+{domainFirewallCreated} created)");
        }

        state.Db.SetSchedules(policy.Schedules.Select(s => (s.Target, s.Days, s.Start, s.End)));
        state.Schedules.Kick();
        summary.Add($"{policy.Schedules.Count} schedules");

        // ── Profiles ──
        foreach (var p in policy.Profiles)
        {
            if (string.IsNullOrWhiteSpace(p.Name))
            {
                continue;
            }

            state.Db.ImportProfile(p.Name, p.Rules.Select(r => (r.Domain, r.Status, (string?)r.Source)));
        }

        summary.Add($"{policy.Profiles.Count} profiles");

        // ── Settings lock ──
        state.Lock.ImportState(policy.Lock.Enabled, policy.Lock.Hash);
        summary.Add(policy.Lock.Enabled ? "settings lock armed" : "settings lock disarmed");

        // ── Network→profile mappings ──
        foreach (var n in policy.NetworkProfiles)
        {
            if (!string.IsNullOrWhiteSpace(n.Fingerprint))
            {
                state.Db.SetNetworkProfile(n.Fingerprint, n.Profile ?? string.Empty, n.Label ?? string.Empty);
            }
        }

        summary.Add($"{policy.NetworkProfiles.Count} network profiles");

        // ── Rule groups (NET-103) ──
        foreach (var g in policy.RuleGroups)
        {
            if (string.IsNullOrWhiteSpace(g.Name))
            {
                continue;
            }

            foreach (var rule in g.Rules.Where(r => !string.IsNullOrWhiteSpace(r)))
            {
                state.Db.AssignRuleToGroup(rule, g.Name);
            }
        }

        summary.Add($"{policy.RuleGroups.Count} rule groups");

        // ── Blocklist subscriptions (a later refresh re-imports domains) ──
        foreach (var b in policy.BlocklistSubs)
        {
            if (!string.IsNullOrWhiteSpace(b.Name) && !string.IsNullOrWhiteSpace(b.Url))
            {
                state.Db.UpsertBlocklistSub(b.Name, b.Url, 0);
            }
        }

        // ── IP blocklists (a later refresh re-applies HG_IPBlock_* rules) ──
        foreach (var b in policy.IpBlocklists)
        {
            if (!string.IsNullOrWhiteSpace(b.Name) && !string.IsNullOrWhiteSpace(b.Url))
            {
                state.Db.UpsertIpBlocklistSubscription(b.Name, b.Url, b.Enabled);
            }
        }

        // ── Allowlist subscriptions (replace-all) ──
        state.Db.SetAllowlistSubs(policy.AllowlistSubs.Where(u => !string.IsNullOrWhiteSpace(u)));
        summary.Add($"{policy.BlocklistSubs.Count} blocklist + {policy.AllowlistSubs.Count} allowlist subscriptions");

        ApplyConsent(state, policy, summary);
        ApplyDnsPrivacy(state, policy, summary);
        ApplyKillSwitch(state, policy, summary);
        ApplyAppVpnBindings(state, policy, summary);
        ApplyUsageQuotas(state, policy, summary);
        ApplyLanAttackSurface(state, policy, summary);
        ApplyAi(state, policy, summary);
        ApplyWebhooks(state, policy, summary);

        // ── Carried meta settings ──
        foreach (var (key, value) in policy.Settings)
        {
            if (PortableMetaKeys.Contains(key, StringComparer.Ordinal))
            {
                state.Db.SetMeta(key, value);
            }
        }

        state.Db.LogEvent("policy", "imported", details:
            $"{policy.Domains.Count} domains, {policy.FirewallRules.Count} fw rules, {policy.Profiles.Count} profiles", reason: "manual");
        return summary;
    }

    public static IReadOnlyList<string> Restore(ServiceState state, PortablePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(policy);
        var summary = new List<string>();

        state.Db.ReplaceDomains(policy.Domains
            .Where(d => !string.IsNullOrWhiteSpace(d.Domain))
            .Select(d => (d.Domain, d.Status, (string?)d.Source)));
        foreach (var d in policy.Domains)
        {
            if (string.IsNullOrWhiteSpace(d.Domain))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(d.Category))
            {
                state.Db.SetCategory(d.Domain, d.Category);
            }

            if (!string.IsNullOrWhiteSpace(d.Notes))
            {
                state.Db.SetNotes(d.Domain, d.Notes);
            }
        }

        var blocked = state.Db.GetDomains(status: "blocked").Select(r => r.Domain).ToList();
        var (added, target) = state.Hosts.Reconcile(blocked);
        summary.Add($"{policy.Domains.Count} domains restored ({target} blocked, +{added} hosts reconcile)");

        state.Db.SetSchedules(policy.Schedules.Select(s => (s.Target, s.Days, s.Start, s.End)));
        state.Schedules.Kick();
        summary.Add($"{policy.Schedules.Count} schedules restored");

        if (state.Firewall is { } fw)
        {
            var desiredRules = policy.FirewallRules
                .Where(r => !string.IsNullOrWhiteSpace(r.Name))
                .Select(r => r.Name)
                .ToHashSet(StringComparer.Ordinal);
            var removedRules = 0;
            foreach (var existing in fw.ListRules()
                         .Where(r => r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal)
                             && !desiredRules.Contains(r.Name))
                         .ToList())
            {
                if (fw.DeleteRule(existing.Name))
                {
                    removedRules++;
                }

                state.Db.RemoveFwState(existing.Name);
            }

            var createdRules = 0;
            foreach (var r in policy.FirewallRules)
            {
                if (string.IsNullOrWhiteSpace(r.Name) ||
                    !r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                var rule = ToFirewallRule(r);
                if (fw.CreateRule(rule))
                {
                    createdRules++;
                }

                state.Db.UpsertFwState(
                    rule.Name,
                    rule.Direction,
                    rule.Action,
                    rule.RemoteAddr,
                    rule.Protocol,
                    rule.Program,
                    rule.RemotePorts,
                    rule.LocalPorts,
                    rule.ServiceName,
                    rule.Interfaces,
                    rule.PackageFamilyName,
                    rule.PackageSid,
                    rule.PackageDisplayName,
                    rule.PackageFullName,
                    rule.PackageBinaries);
            }

            summary.Add($"{policy.FirewallRules.Count} firewall rules restored (+{createdRules}, -{removedRules})");
        }

        foreach (var name in state.Db.ListProfiles().Where(n => !policy.Profiles.Any(p => p.Name == n)).ToList())
        {
            state.Db.DeleteProfile(name);
        }

        foreach (var p in policy.Profiles)
        {
            if (!string.IsNullOrWhiteSpace(p.Name))
            {
                state.Db.ImportProfile(p.Name, p.Rules.Select(r => (r.Domain, r.Status, (string?)r.Source)));
            }
        }

        summary.Add($"{policy.Profiles.Count} profiles restored");

        foreach (var current in state.Db.GetBlocklistSubs().Where(s => policy.BlocklistSubs.All(p => p.Name != s.Name)).ToList())
        {
            state.Db.RemoveBlocklistSub(current.Name);
        }

        foreach (var b in policy.BlocklistSubs)
        {
            if (!string.IsNullOrWhiteSpace(b.Name) && !string.IsNullOrWhiteSpace(b.Url))
            {
                state.Db.UpsertBlocklistSub(b.Name, b.Url, 0);
            }
        }

        foreach (var current in state.Db.GetIpBlocklistSources().Where(s => policy.IpBlocklists.All(p => p.Name != s.Name)).ToList())
        {
            if (state.IpBlocklists is { } coordinator)
            {
                coordinator.Remove(current.Name);
            }
            else
            {
                state.Db.RemoveIpBlocklistSource(current.Name);
            }
        }

        foreach (var b in policy.IpBlocklists)
        {
            if (!string.IsNullOrWhiteSpace(b.Name) && !string.IsNullOrWhiteSpace(b.Url))
            {
                state.Db.UpsertIpBlocklistSubscription(b.Name, b.Url, b.Enabled);
            }
        }

        state.Db.SetAllowlistSubs(policy.AllowlistSubs.Where(u => !string.IsNullOrWhiteSpace(u)));
        summary.Add($"{policy.BlocklistSubs.Count} blocklist + {policy.AllowlistSubs.Count} allowlist subscriptions restored");

        ApplyConsent(state, policy, summary);
        ApplyDnsPrivacy(state, policy, summary);
        ApplyKillSwitch(state, policy, summary);
        ApplyAppVpnBindings(state, policy, summary);
        ApplyUsageQuotas(state, policy, summary);
        ApplyLanAttackSurface(state, policy, summary);
        ApplyAi(state, policy, summary);
        ApplyWebhooks(state, policy, summary);

        foreach (var (key, value) in policy.Settings)
        {
            if (PortableMetaKeys.Contains(key, StringComparer.Ordinal))
            {
                state.Db.SetMeta(key, value);
            }
        }

        state.Db.LogEvent("policy", "checkpoint_restored", details:
            $"{policy.Domains.Count} domains, {policy.Profiles.Count} profiles", reason: "manual");
        return summary;
    }

    private static void ApplyConsent(ServiceState state, PortablePolicy policy, List<string> summary)
    {
        if (policy.Consent is not { } c)
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(c.Mode))
        {
            state.Consent.SetMode(c.Mode);
        }

        if (c.ChildInherit is { } childInherit)
        {
            state.Consent.SetChildInherit(childInherit);
        }

        if (c.InboundConsent is { } inboundConsent)
        {
            state.Consent.SetInboundConsent(inboundConsent);
        }

        if (c.TrustedPublishers is { } publishers)
        {
            state.Consent.SetTrustedPublishers(publishers);
        }

        if (c.TrustedFolders is { } folders)
        {
            state.Consent.SetTrustedFolders(folders);
        }

        summary.Add("consent posture + trust sets");
    }

    private static void ApplyDnsPrivacy(ServiceState state, PortablePolicy policy, List<string> summary)
    {
        if (policy.DnsPrivacy is not { } dns)
        {
            return;
        }

        if (dns.DohIntelligence is { } importedDoh)
        {
            state.Doh.Import(new DohState
            {
                Updated = importedDoh.Updated,
                Source = importedDoh.Source.Length != 0 ? importedDoh.Source : "Portable policy",
                Sha256 = importedDoh.Sha256,
                Ips = importedDoh.Ips ?? new List<string>(),
            });
        }

        if (dns.CnameCloak is { } cname)
        {
            state.CnameCloak.SetEnabled(cname);
        }

        if (dns.SniCapture is { } sni)
        {
            state.Db.SetMeta("sni_capture", sni ? "on" : "off");
            if (state.Sni is { } sniffer)
            {
                if (sni)
                {
                    sniffer.Start();
                }
                else
                {
                    sniffer.Stop();
                }
            }
        }

        if (state.Firewall is not null)
        {
            var fw = new FirewallControlServiceImpl(state);
            if (dns.DohBlocking is { } dohBlock)
            {
                _ = dohBlock
                    ? fw.BlockEncryptedDns(new DohBlockRequest(), null!).GetAwaiter().GetResult()
                    : fw.UnblockEncryptedDns(new Empty(), null!).GetAwaiter().GetResult();
            }

            if (dns.QuicBlocked is { } quic)
            {
                _ = quic
                    ? fw.BlockQuic(new Empty(), null!).GetAwaiter().GetResult()
                    : fw.UnblockQuic(new Empty(), null!).GetAwaiter().GetResult();
            }
        }

        summary.Add("DNS privacy posture");
    }

    private static void ApplyKillSwitch(ServiceState state, PortablePolicy policy, List<string> summary)
    {
        if (policy.KillSwitch?.Enabled is not { } enabled)
        {
            return;
        }

        if (state.KillSwitch is not { } killSwitch)
        {
            summary.Add("kill-switch skipped (monitor unavailable)");
            return;
        }

        var adapter = policy.KillSwitch.Adapter ?? string.Empty;
        var ack = killSwitch.Configure(enabled, adapter);
        summary.Add(ack.Ok ? "kill-switch policy" : $"kill-switch skipped ({ack.Message})");
    }

    private static void ApplyAppVpnBindings(ServiceState state, PortablePolicy policy, List<string> summary)
    {
        if (policy.AppVpnBindings.Count == 0)
        {
            return;
        }

        if (state.AppVpnBindings is not { } bindings)
        {
            summary.Add($"{policy.AppVpnBindings.Count} app VPN bindings skipped (coordinator unavailable)");
            return;
        }

        var applied = 0;
        foreach (var binding in policy.AppVpnBindings)
        {
            if (string.IsNullOrWhiteSpace(binding.Program) || string.IsNullOrWhiteSpace(binding.Adapter))
            {
                continue;
            }

            var ack = bindings.Set(binding.Program, binding.Adapter, enabled: true);
            if (ack.Ok)
            {
                applied++;
            }
        }

        summary.Add($"{policy.AppVpnBindings.Count} app VPN bindings ({applied} applied)");
    }

    private static void ApplyUsageQuotas(ServiceState state, PortablePolicy policy, List<string> summary)
    {
        if (policy.UsageQuotas is not { } quotas)
        {
            return;
        }

        state.Db.ReplaceUsageQuotaRules(quotas.Select(q => (
            q.Scope,
            q.Match,
            q.LimitBytes,
            q.WindowDays,
            q.Enabled)));
        summary.Add($"{quotas.Count} usage quota rule{(quotas.Count == 1 ? string.Empty : "s")}");
    }

    private static void ApplyLanAttackSurface(ServiceState state, PortablePolicy policy, List<string> summary)
    {
        if (policy.LanAttackSurface?.Toggles is not { Count: > 0 } toggles)
        {
            return;
        }

        var applied = 0;
        foreach (var toggle in toggles)
        {
            if (string.IsNullOrWhiteSpace(toggle.Key))
            {
                continue;
            }

            var ack = state.LanAttackSurface.Set(toggle.Key, toggle.Blocked);
            if (ack.Ok)
            {
                applied++;
            }
        }

        summary.Add($"{applied} LAN attack-surface toggles");
    }

    private static void ApplyAi(ServiceState state, PortablePolicy policy, List<string> summary)
    {
        if (policy.Ai is { } ai)
        {
            var current = state.Ai.Settings;
            state.Ai.SaveSettings(
                apiKey: string.Empty,
                model: NonEmpty(ai.Model, current.Model),
                endpoint: NonEmpty(ai.Endpoint, current.Endpoint),
                enabled: ai.Enabled ?? current.Enabled);

            SetMetaIfNotNull(state, "ai_last_run", ai.LastRun);
            SetMetaIfNotNull(state, "ai_last_result", ai.LastResult);
            SetMetaIfNotNull(state, "ai_knowledge_reviewed_at", ai.LastReviewed);
        }

        var knowledge = 0;
        foreach (var k in policy.AiKnowledge ?? Enumerable.Empty<PolicyAiKnowledge>())
        {
            if (string.IsNullOrWhiteSpace(k.Kind) || string.IsNullOrWhiteSpace(k.Key))
            {
                continue;
            }

            state.Db.UpsertAiKnowledge(k.Kind, k.Key, k.Value ?? string.Empty, k.Model ?? string.Empty);
            knowledge++;
        }

        var overrides = 0;
        foreach (var o in policy.UserOverrides ?? Enumerable.Empty<PolicyUserOverride>())
        {
            if (string.IsNullOrWhiteSpace(o.Kind) || string.IsNullOrWhiteSpace(o.Key))
            {
                continue;
            }

            state.Db.UpsertUserOverride(o.Kind, o.Key, o.Value ?? string.Empty);
            overrides++;
        }

        if (policy.Ai is not null || knowledge != 0 || overrides != 0)
        {
            summary.Add($"AI policy ({knowledge} learned, {overrides} overrides; API key omitted)");
        }
    }

    private static void ApplyWebhooks(ServiceState state, PortablePolicy policy, List<string> summary)
    {
        if (policy.Webhooks?.Urls is not { } urls)
        {
            return;
        }

        var accepted = new List<string>();
        var rejected = 0;
        foreach (var url in urls.Select(u => (u ?? string.Empty).Trim()).Where(u => u.Length != 0))
        {
            try
            {
                SsrfGuard.EnsurePublicHttpsAsync(url, CancellationToken.None).GetAwaiter().GetResult();
                accepted.Add(url);
            }
            catch (SsrfBlockedException)
            {
                rejected++;
            }
        }

        state.Webhooks.Urls = accepted;
        state.Webhooks.Save(state.DataDir);
        summary.Add($"{accepted.Count} webhook endpoint(s), {rejected} rejected; secret omitted");
    }

    private static void SetMetaIfNotNull(ServiceState state, string key, string? value)
    {
        if (value is not null)
        {
            state.Db.SetMeta(key, value);
        }
    }

    private static string NonEmpty(string? value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private static FwRule ToFirewallRule(PolicyFirewallRule r) => new(
        r.Name,
        FwRuleMapper.MapDirection(r.Direction),
        FwRuleMapper.MapAction(r.Action),
        r.Enabled,
        string.IsNullOrWhiteSpace(r.RemoteAddr) ? "Any" : r.RemoteAddr,
        FwRuleMapper.MapProtocol(r.Protocol),
        r.Program ?? string.Empty,
        "hostsguard",
        FwRuleMapper.MapPorts(r.RemotePorts),
        FwRuleMapper.MapService(r.ServiceName),
        FwRuleMapper.MapPorts(r.LocalPorts),
        FwRuleMapper.MapInterfaces(r.Interfaces),
        r.PackageFamilyName ?? string.Empty,
        r.PackageSid ?? string.Empty,
        r.PackageDisplayName ?? string.Empty,
        r.PackageFullName ?? string.Empty,
        r.PackageBinaries ?? string.Empty);

    private static void AddSetDiff(
        string label,
        IReadOnlySet<string> current,
        IReadOnlySet<string> desired,
        List<string> summary,
        ref long added,
        ref long removed,
        bool removeMissing = true)
    {
        var add = desired.Count(item => !current.Contains(item));
        var remove = removeMissing ? current.Count(item => !desired.Contains(item)) : 0;
        added += add;
        removed += remove;
        summary.Add($"{label}: +{add}, ~0, -{remove}{(removeMissing ? string.Empty : " (merge)")}");
    }

    private static string AppVersion() =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0]
        ?? "unknown";
}
