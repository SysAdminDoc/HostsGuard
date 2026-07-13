using Dapper;

namespace HostsGuard.Data;

public sealed record BinaryNetworkFirstSeenRow(
    string Identity, string Process, string Path, string Sha256, string Signer, string Destination, string FirstSeen);

public sealed partial class HostsDatabase
{
    public bool TryRecordBinaryNetworkFirstSeen(BinaryNetworkFirstSeenRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (string.IsNullOrWhiteSpace(row.Identity)) throw new ArgumentException("binary identity is required", nameof(row));
        lock (_gate)
            return _conn.Execute("""
                INSERT OR IGNORE INTO binary_network_first_seen(identity,process,path,sha256,signer,destination,first_seen)
                VALUES(@Identity,@Process,@Path,@Sha256,@Signer,@Destination,@FirstSeen)
                """, row) != 0;
    }

    public IReadOnlyList<BinaryNetworkFirstSeenRow> GetBinaryNetworkFirstSeen()
    {
        lock (_gate)
            return _conn.Query<BinaryNetworkFirstSeenRow>(
                "SELECT identity,process,path,sha256,signer,destination,first_seen AS FirstSeen FROM binary_network_first_seen ORDER BY first_seen")
                .ToList();
    }
}
