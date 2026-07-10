namespace HostsGuard.Core;

/// <summary>
/// A parsed SVCB/HTTPS resource record (RFC 9460) as used by DDR (RFC 9462) to
/// advertise a network's designated encrypted resolver, and RFC 9461 to carry
/// the DoH template. Only the fields HostsGuard surfaces are extracted.
/// </summary>
public sealed record DesignatedResolverRecord(
    int Priority,
    string TargetName,
    IReadOnlyList<string> Alpn,
    int? Port,
    string? DohPath)
{
    /// <summary>True when the record advertises an encrypted transport (DoH/DoT/DoQ).</summary>
    public bool IsEncrypted =>
        Alpn.Any(a => a is "h2" or "h3" or "dot" or "doq"
            || a.StartsWith("h3", StringComparison.Ordinal));

    /// <summary>Discovered DoH endpoint (https://target + dohpath), when this is a DoH record.</summary>
    public string? DohEndpoint =>
        DohPath is { Length: > 0 } && TargetName.Length > 0
            ? $"https://{TargetName}{DohPath.Replace("{?dns}", string.Empty, StringComparison.Ordinal)}"
            : null;
}

/// <summary>
/// Minimal SVCB/HTTPS RDATA wire parser (RFC 9460 §2.2, RFC 9461 dohpath) for the
/// DDR designated-resolver observer (NET-173). Deliberately tolerant and
/// non-throwing: a malformed record yields <c>null</c> rather than an exception,
/// because it parses untrusted bytes off the wire / the Windows resolver cache.
/// </summary>
public static class DesignatedResolver
{
    private const int KeyAlpn = 1;
    private const int KeyPort = 3;
    private const int KeyDohPath = 7; // RFC 9461

    /// <summary>
    /// Parse SVCB/HTTPS RDATA: 2-byte SvcPriority, an uncompressed target name
    /// (length-prefixed labels terminated by a zero label), then a sequence of
    /// SvcParams {2-byte key, 2-byte length, value}. Returns null on any overrun.
    /// </summary>
    public static DesignatedResolverRecord? ParseSvcb(ReadOnlySpan<byte> rdata)
    {
        try
        {
            var pos = 0;
            if (rdata.Length < 3)
            {
                return null;
            }

            var priority = (rdata[pos] << 8) | rdata[pos + 1];
            pos += 2;

            var target = ReadName(rdata, ref pos);
            if (target is null)
            {
                return null;
            }

            var alpn = new List<string>();
            int? port = null;
            string? dohPath = null;

            while (pos + 4 <= rdata.Length)
            {
                var key = (rdata[pos] << 8) | rdata[pos + 1];
                var len = (rdata[pos + 2] << 8) | rdata[pos + 3];
                pos += 4;
                if (pos + len > rdata.Length)
                {
                    return null;
                }

                var value = rdata.Slice(pos, len);
                switch (key)
                {
                    case KeyAlpn:
                        alpn.AddRange(ReadAlpnList(value));
                        break;
                    case KeyPort when len >= 2:
                        port = (value[0] << 8) | value[1];
                        break;
                    case KeyDohPath:
                        dohPath = System.Text.Encoding.ASCII.GetString(value);
                        break;
                }

                pos += len;
            }

            return new DesignatedResolverRecord(priority, target, alpn, port, dohPath);
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException)
        {
            return null;
        }
    }

    private static string? ReadName(ReadOnlySpan<byte> data, ref int pos)
    {
        var labels = new List<string>();
        while (pos < data.Length)
        {
            var len = data[pos++];
            if (len == 0)
            {
                return string.Join('.', labels);
            }

            // Compression pointers are not valid in SVCB TargetName (RFC 9460 §2.2).
            if ((len & 0xC0) != 0 || pos + len > data.Length)
            {
                return null;
            }

            labels.Add(System.Text.Encoding.ASCII.GetString(data.Slice(pos, len)));
            pos += len;
        }

        return null; // ran off the end without a terminating zero label
    }

    private static IEnumerable<string> ReadAlpnList(ReadOnlySpan<byte> value)
    {
        var result = new List<string>();
        var i = 0;
        while (i < value.Length)
        {
            var len = value[i++];
            if (len == 0 || i + len > value.Length)
            {
                break;
            }

            result.Add(System.Text.Encoding.ASCII.GetString(value.Slice(i, len)));
            i += len;
        }

        return result;
    }
}
