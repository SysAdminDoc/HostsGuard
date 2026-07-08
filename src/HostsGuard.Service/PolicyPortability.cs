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
                .Where(r => r.Name.StartsWith(FwRuleMapper.HostsGuardPrefix, StringComparison.Ordinal)))
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
                    RemotePorts = r.RemotePorts,
                    ServiceName = r.ServiceName,
                });
            }
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

                var rule = new FwRule(
                    r.Name,
                    FwRuleMapper.MapDirection(r.Direction),
                    FwRuleMapper.MapAction(r.Action),
                    r.Enabled,
                    string.IsNullOrWhiteSpace(r.RemoteAddr) ? "Any" : r.RemoteAddr,
                    FwRuleMapper.MapProtocol(r.Protocol),
                    r.Program ?? string.Empty,
                    "hostsguard",
                    FwRuleMapper.MapPorts(r.RemotePorts),
                    FwRuleMapper.MapService(r.ServiceName));
                if (fw.CreateRule(rule))
                {
                    rulesCreated++;
                }

                // Track even pre-existing rules so drift detection stays accurate.
                state.Db.UpsertFwState(rule.Name, rule.Direction, rule.Action, rule.RemoteAddr, rule.Protocol, rule.Program);
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

        // ── Allowlist subscriptions (replace-all) ──
        state.Db.SetAllowlistSubs(policy.AllowlistSubs.Where(u => !string.IsNullOrWhiteSpace(u)));
        summary.Add($"{policy.BlocklistSubs.Count} blocklist + {policy.AllowlistSubs.Count} allowlist subscriptions");

        ApplyConsent(state, policy, summary);
        ApplyDnsPrivacy(state, policy, summary);
        ApplyKillSwitch(state, policy, summary);
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

    private static string AppVersion() =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0]
        ?? "unknown";
}
