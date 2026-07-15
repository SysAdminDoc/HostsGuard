using Dapper;

namespace HostsGuard.Data;

public sealed record HostsRedirectRow(string Domain, string Ip, string Created, string Modified);

public sealed partial class HostsDatabase
{
    public IReadOnlyList<HostsRedirectRow> GetHostsRedirects()
    {
        lock (_gate)
        {
            return _conn.Query<HostsRedirectRow>(
                "SELECT domain, ip, created, modified FROM hosts_redirects ORDER BY domain").ToList();
        }
    }

    public void UpsertHostsRedirect(string domain, string ip)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            _conn.Execute(
                """
                INSERT INTO hosts_redirects(domain,ip,created,modified)
                VALUES(@domain,@ip,@now,@now)
                ON CONFLICT(domain) DO UPDATE SET ip=excluded.ip, modified=excluded.modified
                """,
                new { domain, ip, now });
        }
    }

    public bool RemoveHostsRedirect(string domain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        lock (_gate)
        {
            return _conn.Execute("DELETE FROM hosts_redirects WHERE domain=@domain", new { domain }) != 0;
        }
    }

    public void ReplaceHostsRedirects(IEnumerable<(string Domain, string Ip)> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM hosts_redirects", transaction: tx);
            foreach (var (domain, ip) in rows)
            {
                _conn.Execute(
                    "INSERT INTO hosts_redirects(domain,ip,created,modified) VALUES(@domain,@ip,@now,@now)",
                    new { domain, ip, now }, tx);
            }

            tx.Commit();
        }
    }
}
