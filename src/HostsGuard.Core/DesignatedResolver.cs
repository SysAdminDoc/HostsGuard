using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace HostsGuard.Core;

/// <summary>An unrecognized but well-formed SVCB parameter.</summary>
public sealed record SvcbUnknownParameter(ushort Key, byte[] Value);

/// <summary>
/// A parsed SVCB/HTTPS resource record (RFC 9460), including the parameters
/// registered for encrypted DNS discovery and HTTPS endpoint selection.
/// </summary>
public sealed record DesignatedResolverRecord
{
    public DesignatedResolverRecord(
        int priority,
        string targetName,
        IReadOnlyList<string> alpn,
        int? port,
        string? dohPath)
        : this(
            priority,
            targetName,
            Array.Empty<ushort>(),
            alpn,
            false,
            port,
            Array.Empty<string>(),
            null,
            Array.Empty<string>(),
            dohPath,
            Array.Empty<SvcbUnknownParameter>())
    {
    }

    internal DesignatedResolverRecord(
        int priority,
        string targetName,
        IReadOnlyList<ushort> mandatoryKeys,
        IReadOnlyList<string> alpn,
        bool noDefaultAlpn,
        int? port,
        IReadOnlyList<string> ipv4Hints,
        byte[]? ech,
        IReadOnlyList<string> ipv6Hints,
        string? dohPath,
        IReadOnlyList<SvcbUnknownParameter> unknownParameters)
    {
        Priority = priority;
        TargetName = targetName;
        MandatoryKeys = mandatoryKeys;
        Alpn = alpn;
        NoDefaultAlpn = noDefaultAlpn;
        Port = port;
        Ipv4Hints = ipv4Hints;
        Ech = ech;
        Ipv6Hints = ipv6Hints;
        DohPath = dohPath;
        UnknownParameters = unknownParameters;
    }

    public int Priority { get; }
    public string TargetName { get; }
    public IReadOnlyList<ushort> MandatoryKeys { get; }
    public IReadOnlyList<string> Alpn { get; }
    public bool NoDefaultAlpn { get; }
    public int? Port { get; }
    public IReadOnlyList<string> Ipv4Hints { get; }
    public byte[]? Ech { get; }
    public IReadOnlyList<string> Ipv6Hints { get; }
    public string? DohPath { get; }
    public IReadOnlyList<SvcbUnknownParameter> UnknownParameters { get; }

    public void Deconstruct(
        out int priority,
        out string targetName,
        out IReadOnlyList<string> alpn,
        out int? port,
        out string? dohPath)
    {
        priority = Priority;
        targetName = TargetName;
        alpn = Alpn;
        port = Port;
        dohPath = DohPath;
    }

    /// <summary>True when ECH configuration bytes were advertised in this record.</summary>
    public bool EchAdvertised => Ech is not null;

    /// <summary>
    /// True when a mandatory parameter is syntactically valid but unknown to this
    /// implementation. RFC 9460 requires consumers to ignore such a record.
    /// </summary>
    public bool HasUnsupportedMandatoryKeys =>
        MandatoryKeys.Any(key => !DesignatedResolver.IsSupportedKey(key));

    /// <summary>True when the record advertises an encrypted transport (DoH/DoT/DoQ).</summary>
    public bool IsEncrypted =>
        Alpn.Any(a => a is "h2" or "h3" or "dot" or "doq"
            || a.StartsWith("h3", StringComparison.Ordinal));

    /// <summary>Discovered DoH endpoint (https://target + dohpath), when this is a DoH record.</summary>
    public string? DohEndpoint =>
        DohPath is { Length: > 0 } && TargetName is not "."
            ? $"https://{TargetName}{DohPath.Replace("{?dns}", string.Empty, StringComparison.Ordinal)}"
            : null;
}

/// <summary>
/// Strict, non-throwing SVCB/HTTPS RDATA wire parser (RFC 9460 section 2.2 and
/// RFC 9461). Invalid records return <c>null</c>; valid unknown parameters are
/// retained so callers can distinguish extension data from malformed input.
/// </summary>
public static class DesignatedResolver
{
    private const ushort KeyMandatory = 0;
    private const ushort KeyAlpn = 1;
    private const ushort KeyNoDefaultAlpn = 2;
    private const ushort KeyPort = 3;
    private const ushort KeyIpv4Hint = 4;
    private const ushort KeyEch = 5;
    private const ushort KeyIpv6Hint = 6;
    private const ushort KeyDohPath = 7;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static bool IsSupportedKey(ushort key) => key <= KeyDohPath;

    /// <summary>
    /// Parses an exact RDATA field: two-byte SvcPriority, one uncompressed DNS
    /// TargetName, and zero or more strictly increasing SvcParams.
    /// </summary>
    public static DesignatedResolverRecord? ParseSvcb(ReadOnlySpan<byte> rdata)
    {
        try
        {
            if (rdata.Length < 3)
            {
                return null;
            }

            var priority = BinaryPrimitives.ReadUInt16BigEndian(rdata);
            var pos = 2;
            var target = ReadName(rdata, ref pos);
            if (target is null)
            {
                return null;
            }

            var mandatory = new List<ushort>();
            var alpn = new List<string>();
            var noDefaultAlpn = false;
            int? port = null;
            var ipv4Hints = new List<string>();
            byte[]? ech = null;
            var ipv6Hints = new List<string>();
            string? dohPath = null;
            var unknown = new List<SvcbUnknownParameter>();
            var presentKeys = new HashSet<ushort>();
            int previousKey = -1;

            while (pos < rdata.Length)
            {
                if (rdata.Length - pos < 4)
                {
                    return null;
                }

                var key = BinaryPrimitives.ReadUInt16BigEndian(rdata[pos..]);
                var length = BinaryPrimitives.ReadUInt16BigEndian(rdata[(pos + 2)..]);
                pos += 4;
                if (key <= previousKey || length > rdata.Length - pos)
                {
                    return null;
                }

                previousKey = key;
                presentKeys.Add(key);
                var value = rdata.Slice(pos, length);
                pos += length;

                switch (key)
                {
                    case KeyMandatory:
                        if (!ReadMandatory(value, mandatory))
                        {
                            return null;
                        }
                        break;
                    case KeyAlpn:
                        if (!ReadAlpnList(value, alpn))
                        {
                            return null;
                        }
                        break;
                    case KeyNoDefaultAlpn:
                        if (!value.IsEmpty)
                        {
                            return null;
                        }
                        noDefaultAlpn = true;
                        break;
                    case KeyPort:
                        if (value.Length != 2)
                        {
                            return null;
                        }
                        port = BinaryPrimitives.ReadUInt16BigEndian(value);
                        break;
                    case KeyIpv4Hint:
                        if (!ReadAddresses(value, 4, ipv4Hints))
                        {
                            return null;
                        }
                        break;
                    case KeyEch:
                        if (value.IsEmpty)
                        {
                            return null;
                        }
                        ech = value.ToArray();
                        break;
                    case KeyIpv6Hint:
                        if (!ReadAddresses(value, 16, ipv6Hints))
                        {
                            return null;
                        }
                        break;
                    case KeyDohPath:
                        if (!ReadDohPath(value, out dohPath))
                        {
                            return null;
                        }
                        break;
                    default:
                        unknown.Add(new SvcbUnknownParameter(key, value.ToArray()));
                        break;
                }
            }

            // AliasMode cannot carry parameters and cannot alias to the root.
            if (priority == 0 && (presentKeys.Count != 0 || target == "."))
            {
                return null;
            }

            // no-default-alpn is meaningless without an explicit ALPN list.
            if (noDefaultAlpn && !presentKeys.Contains(KeyAlpn))
            {
                return null;
            }

            // Mandatory keys must name parameters actually present in this record.
            if (mandatory.Any(key => !presentKeys.Contains(key)))
            {
                return null;
            }

            return new DesignatedResolverRecord(
                priority,
                target,
                mandatory.AsReadOnly(),
                alpn.AsReadOnly(),
                noDefaultAlpn,
                port,
                ipv4Hints.AsReadOnly(),
                ech,
                ipv6Hints.AsReadOnly(),
                dohPath,
                unknown.AsReadOnly());
        }
        catch (Exception ex) when (ex is ArgumentException or DecoderFallbackException)
        {
            return null;
        }
    }

    private static string? ReadName(ReadOnlySpan<byte> data, ref int pos)
    {
        var labels = new List<string>();
        var wireLength = 0;
        while (pos < data.Length)
        {
            var length = data[pos++];
            wireLength++;
            if (wireLength > 255)
            {
                return null;
            }

            if (length == 0)
            {
                return labels.Count == 0 ? "." : string.Join('.', labels);
            }

            // Compression and extended label types are forbidden in SVCB TargetName.
            if (length > 63 || length > data.Length - pos || wireLength + length > 255)
            {
                return null;
            }

            labels.Add(EscapeDnsLabel(data.Slice(pos, length)));
            pos += length;
            wireLength += length;
        }

        return null;
    }

    private static string EscapeDnsLabel(ReadOnlySpan<byte> label)
    {
        var result = new StringBuilder(label.Length);
        foreach (var value in label)
        {
            if (value is >= 0x21 and <= 0x7e && value is not (byte)'.' and not (byte)'\\')
            {
                result.Append((char)value);
            }
            else
            {
                result.Append('\\').Append(value.ToString("D3", System.Globalization.CultureInfo.InvariantCulture));
            }
        }

        return result.ToString();
    }

    private static bool ReadMandatory(ReadOnlySpan<byte> value, List<ushort> destination)
    {
        if (value.IsEmpty || value.Length % 2 != 0)
        {
            return false;
        }

        int previous = -1;
        for (var pos = 0; pos < value.Length; pos += 2)
        {
            var key = BinaryPrimitives.ReadUInt16BigEndian(value[pos..]);
            if (key == KeyMandatory || key <= previous)
            {
                return false;
            }

            previous = key;
            destination.Add(key);
        }

        return true;
    }

    private static bool ReadAlpnList(ReadOnlySpan<byte> value, List<string> destination)
    {
        if (value.IsEmpty)
        {
            return false;
        }

        var pos = 0;
        while (pos < value.Length)
        {
            var length = value[pos++];
            if (length == 0 || length > value.Length - pos)
            {
                return false;
            }

            // ALPN protocol IDs are opaque octets; Latin-1 provides a lossless
            // one-byte-to-one-character representation while preserving the API.
            destination.Add(Encoding.Latin1.GetString(value.Slice(pos, length)));
            pos += length;
        }

        return true;
    }

    private static bool ReadAddresses(ReadOnlySpan<byte> value, int addressLength, List<string> destination)
    {
        if (value.IsEmpty || value.Length % addressLength != 0)
        {
            return false;
        }

        for (var pos = 0; pos < value.Length; pos += addressLength)
        {
            destination.Add(new IPAddress(value.Slice(pos, addressLength)).ToString());
        }

        return true;
    }

    private static bool ReadDohPath(ReadOnlySpan<byte> value, out string? path)
    {
        path = null;
        if (value.IsEmpty)
        {
            return false;
        }

        var decoded = StrictUtf8.GetString(value);
        if (!decoded.StartsWith("/", StringComparison.Ordinal) || decoded.Contains('\0'))
        {
            return false;
        }

        path = decoded;
        return true;
    }
}
