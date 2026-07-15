using System.Net;
using Dapper;
using HostsGuard.Core;

namespace HostsGuard.Data;

public sealed record DnsResolutionHopRow(string QueryName, long Position, string Value, string Kind, string Updated);

public sealed partial class HostsDatabase
{
    public void ReplaceDnsResolutionChain(
        string queryName,
        IEnumerable<string> cnames,
        IEnumerable<string> addresses)
    {
        ArgumentNullException.ThrowIfNull(cnames);
        ArgumentNullException.ThrowIfNull(addresses);
        var query = Domains.ToAscii(queryName);
        if (!Domains.LooksLikeDomain(query))
        {
            return;
        }

        var hops = new List<(string Value, string Kind)> { (query, "query") };
        var seen = new HashSet<string>(StringComparer.Ordinal) { query };
        foreach (var raw in cnames.Take(30))
        {
            var cname = Domains.ToAscii(raw);
            if (Domains.LooksLikeDomain(cname) && seen.Add(cname))
            {
                hops.Add((cname, "cname"));
            }
        }

        foreach (var raw in addresses.Take(16))
        {
            if (!IPAddress.TryParse(raw, out var address))
            {
                continue;
            }

            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            var value = address.ToString();
            if (seen.Add(value))
            {
                hops.Add((value, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "A" : "AAAA"));
            }
        }

        var now = DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            using var tx = _conn.BeginTransaction();
            _conn.Execute("DELETE FROM dns_resolution_hops WHERE query_name=@query", new { query }, tx);
            for (var position = 0; position < hops.Count; position++)
            {
                _conn.Execute(
                    "INSERT INTO dns_resolution_hops(query_name,position,value,kind,updated) VALUES(@query,@position,@value,@kind,@now)",
                    new { query, position, value = hops[position].Value, kind = hops[position].Kind, now }, tx);
            }

            tx.Commit();
        }
    }

    public IReadOnlyDictionary<string, IReadOnlyList<DnsResolutionHopRow>> GetDnsResolutionChains(
        IEnumerable<string> queryNames)
    {
        ArgumentNullException.ThrowIfNull(queryNames);
        var result = new Dictionary<string, IReadOnlyList<DnsResolutionHopRow>>(StringComparer.Ordinal);
        lock (_gate)
        {
            foreach (var chunk in queryNames
                .Select(Domains.ToAscii)
                .Where(Domains.LooksLikeDomain)
                .Distinct(StringComparer.Ordinal)
                .Chunk(400))
            {
                var rows = _conn.Query<DnsResolutionHopRow>(
                    """
                    SELECT query_name AS QueryName, position AS Position, value AS Value,
                           kind AS Kind, updated AS Updated
                    FROM dns_resolution_hops
                    WHERE query_name IN @chunk
                    ORDER BY query_name, position
                    """,
                    new { chunk });
                foreach (var group in rows.GroupBy(row => row.QueryName, StringComparer.Ordinal))
                {
                    result[group.Key] = group.ToList();
                }
            }
        }

        return result;
    }
}
