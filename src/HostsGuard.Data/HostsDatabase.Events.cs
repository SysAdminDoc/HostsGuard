using Dapper;
using HostsGuard.Core;

namespace HostsGuard.Data;

public sealed partial class HostsDatabase
{
    public void LogEvent(string domain, string action, string process = "", string details = "", string? reason = null)
    {
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                "INSERT INTO log(ts,domain,action,process,details,reason) VALUES(@now,@domain,@action,@process,@details,@reason)",
                new { now, domain, action, process, details, reason = Reasons.Canonical(reason, "", action, details) });
        }
    }

    public IReadOnlyList<(string Ts, string Domain, string Action, string Process, string Details, string Reason)> GetLog(int limit = 200)
    {
        lock (_gate)
        {
            return _conn.Query<(string, string, string, string, string, string)>(
                "SELECT ts, domain, action, process, details, reason FROM log ORDER BY ts DESC LIMIT @limit",
                new { limit }).ToList();
        }
    }


}
