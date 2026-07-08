using HostsGuard.Contracts;

namespace HostsGuard.Service;

public sealed partial class ConsentBroker
{
    private void LogDecision(string application, string direction, string remote, string protocol, string verdict, bool permanent)
        => _db.LogEvent(
            application,
            $"consent_{verdict}",
            details: $"{direction}|{remote}|{protocol}|{(permanent ? "permanent" : "once")}",
            reason: "consent");

    /// <summary>Read persisted consent decisions back out of the event log.</summary>
    public DecisionHistory History(int limit)
    {
        var history = new DecisionHistory();
        foreach (var row in _db.GetLog(limit is > 0 and <= 2000 ? limit * 4 : 800))
        {
            if (!row.Action.StartsWith("consent_", StringComparison.Ordinal) || row.Action == "consent_once_reaped")
            {
                continue;
            }

            var parts = (row.Details ?? string.Empty).Split('|');
            history.Entries.Add(new DecisionEntry
            {
                DecidedAt = row.Ts,
                Application = row.Domain,
                Direction = parts.Length > 0 ? parts[0] : string.Empty,
                RemoteAddress = parts.Length > 1 ? parts[1] : string.Empty,
                Protocol = parts.Length > 2 ? parts[2] : string.Empty,
                Verdict = row.Action["consent_".Length..],
                Permanent = parts.Length > 3 && parts[3] == "permanent",
            });
            if (history.Entries.Count >= (limit is > 0 and <= 2000 ? limit : 200))
            {
                break;
            }
        }

        return history;
    }

}
