using HostsGuard.Contracts;

namespace HostsGuard.Service;

public sealed partial class ConsentBroker
{
    // â”€â”€â”€ "Decide later" review of Learning-mode auto-decisions (NET-074) â”€â”€â”€â”€â”€

    /// <summary>The Learning-mode auto-allow rules awaiting review.</summary>
    public LearnedList ListLearned()
    {
        var list = new LearnedList();
        if (_firewall is not { } fw)
        {
            return list;
        }

        foreach (var r in fw.ListRules()
                     .Where(r => r.Name.StartsWith(LearnPrefix, StringComparison.Ordinal))
                     .OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
        {
            list.Entries.Add(new LearnedEntry
            {
                RuleName = r.Name,
                Application = r.Program,
                Direction = r.Direction,
                ServiceName = r.ServiceName,
            });
        }

        return list;
    }

    /// <summary>
    /// Apply review verdicts to learned rules: <c>promote</c> converts the
    /// auto-allow into a permanent consent allow, <c>block</c> reverses it into
    /// a permanent consent block, <c>discard</c> just removes it (the app
    /// prompts again next time). Unknown rules/actions are skipped and counted.
    /// </summary>
    public Ack ReviewLearned(LearnedReviewRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (_firewall is not { } fw)
        {
            return new Ack { Ok = false, Message = "firewall engine is not attached to this service instance", ErrorCode = "hostsguard.error.v1/firewall_unavailable" };
        }

        var byName = fw.ListRules()
            .Where(r => r.Name.StartsWith(LearnPrefix, StringComparison.Ordinal))
            .ToDictionary(r => r.Name, StringComparer.Ordinal);
        int promoted = 0, blocked = 0, discarded = 0, skipped = 0;
        foreach (var action in request.Actions)
        {
            if (!byName.TryGetValue(action.RuleName, out var learned))
            {
                skipped++;
                continue;
            }

            var verdict = (action.Action ?? string.Empty).Trim().ToLowerInvariant();
            if (verdict is not ("promote" or "block" or "discard"))
            {
                skipped++;
                continue;
            }

            DeleteRuleTracked(fw, learned.Name);
            _db.RemoveFwState(learned.Name);
            if (verdict == "discard")
            {
                discarded++;
                _db.LogEvent(learned.Program, "consent_discarded", details: $"{learned.Direction}|reviewed", reason: "consent");
                continue;
            }

            var ruleAction = verdict == "promote" ? "Allow" : "Block";
            var stem = Path.GetFileNameWithoutExtension(learned.Program);
            if (learned.ServiceName.Length != 0)
            {
                stem = $"{stem}.{learned.ServiceName}";
            }

            var name = $"{ConsentPrefix}{ruleAction}_{stem}_{learned.Direction}";
            if (!fw.RuleExists(name) &&
                CreateRuleTracked(fw, learned with { Name = name, Action = ruleAction }))
            {
                _db.UpsertFwState(name, learned.Direction, ruleAction, learned.RemoteAddr, learned.Protocol, learned.Program);
                _identity?.Remember(name, learned.Program);
            }

            _ = verdict == "promote" ? promoted++ : blocked++;
            LogDecision(learned.Program, learned.Direction, learned.RemoteAddr, learned.Protocol,
                verdict == "promote" ? "allow" : "block", permanent: true);
        }

        return new Ack
        {
            Ok = true,
            Message = $"reviewed: {promoted} promoted, {blocked} blocked, {discarded} discarded" +
                      (skipped > 0 ? $", {skipped} skipped" : string.Empty),
        };
    }

}
