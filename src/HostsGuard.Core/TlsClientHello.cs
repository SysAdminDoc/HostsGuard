namespace HostsGuard.Core;

/// <summary>
/// Minimal, allocation-light TLS ClientHello parser (NET-109). Extracts the SNI
/// (server_name) hostname from a TLS handshake record so an HTTPS connection can
/// be named even when DNS was resolved out-of-band (DoH). Detects the
/// encrypted_client_hello (ECH) extension: when the real SNI is ECH-encrypted the
/// cleartext name is unavailable, so we report that rather than fabricate a name.
/// Pure — no OS deps — so it's fully unit-testable from crafted bytes.
/// </summary>
public static class TlsClientHello
{
    private const byte HandshakeContentType = 22;
    private const byte ClientHelloType = 1;
    private const ushort ExtServerName = 0x0000;
    private const ushort ExtEncryptedClientHello = 0xfe0d; // draft-ietf-tls-esni ECH

    /// <summary>The outcome of inspecting a candidate TLS ClientHello buffer.</summary>
    public readonly record struct Result(bool Found, string Host, bool EchUnavailable)
    {
        public static Result None => new(false, string.Empty, false);
    }

    /// <summary>
    /// Try to read the SNI host from a TLS record buffer (the start of a TCP
    /// payload). Returns <see cref="Result.Found"/> with the host, or
    /// <c>EchUnavailable</c> when the ClientHello uses ECH (real SNI encrypted).
    /// Never throws — malformed/partial input just yields <see cref="Result.None"/>.
    /// </summary>
    public static Result TryParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            return Parse(buffer);
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return Result.None; // truncated ClientHello (spans segments) — give up cleanly
        }
    }

    private static Result Parse(ReadOnlySpan<byte> b)
    {
        // TLS record header: type(1) version(2) length(2).
        if (b.Length < 5 || b[0] != HandshakeContentType)
        {
            return Result.None;
        }

        var pos = 5;

        // Handshake header: type(1) length(3).
        if (b.Length < pos + 4 || b[pos] != ClientHelloType)
        {
            return Result.None;
        }

        pos += 4;

        // ClientHello: client_version(2) random(32).
        pos += 2 + 32;

        // session_id: length(1) + bytes.
        if (pos >= b.Length)
        {
            return Result.None;
        }

        pos += 1 + b[pos];

        // cipher_suites: length(2) + bytes.
        if (pos + 2 > b.Length)
        {
            return Result.None;
        }

        pos += 2 + ReadU16(b, pos);

        // compression_methods: length(1) + bytes.
        if (pos >= b.Length)
        {
            return Result.None;
        }

        pos += 1 + b[pos];

        // extensions: length(2) + the extension block.
        if (pos + 2 > b.Length)
        {
            return Result.None;
        }

        var extEnd = Math.Min(b.Length, pos + 2 + ReadU16(b, pos));
        pos += 2;

        string? sni = null;
        var ech = false;
        while (pos + 4 <= extEnd)
        {
            var type = ReadU16(b, pos);
            var len = ReadU16(b, pos + 2);
            var dataStart = pos + 4;
            if (dataStart + len > extEnd)
            {
                break;
            }

            switch (type)
            {
                case ExtServerName:
                    sni = ReadServerName(b.Slice(dataStart, len));
                    break;
                case ExtEncryptedClientHello:
                    ech = true;
                    break;
            }

            pos = dataStart + len;
        }

        // ECH means the cleartext SNI (if any) is only the public outer name — the
        // real hostname is encrypted, so report it as unavailable.
        if (ech)
        {
            return new Result(false, string.Empty, true);
        }

        return sni is { Length: > 0 } ? new Result(true, sni, false) : Result.None;
    }

    private static string? ReadServerName(ReadOnlySpan<byte> ext)
    {
        // server_name_list: length(2), then entries of name_type(1) + name(len-prefixed 2).
        if (ext.Length < 2)
        {
            return null;
        }

        var listLen = ReadU16(ext, 0);
        var pos = 2;
        var end = Math.Min(ext.Length, 2 + listLen);
        while (pos + 3 <= end)
        {
            var nameType = ext[pos];
            var nameLen = ReadU16(ext, pos + 1);
            var nameStart = pos + 3;
            if (nameStart + nameLen > end)
            {
                break;
            }

            if (nameType == 0 && nameLen > 0) // host_name
            {
                var host = System.Text.Encoding.ASCII.GetString(ext.Slice(nameStart, nameLen)).Trim().ToLowerInvariant();
                return LooksLikeHost(host) ? host : null;
            }

            pos = nameStart + nameLen;
        }

        return null;
    }

    private static bool LooksLikeHost(string host) =>
        host.Length is > 0 and <= 253 &&
        host.IndexOf('.') > 0 &&
        host.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '.' or '-' or '_');

    private static ushort ReadU16(ReadOnlySpan<byte> b, int offset) => (ushort)((b[offset] << 8) | b[offset + 1]);
}
