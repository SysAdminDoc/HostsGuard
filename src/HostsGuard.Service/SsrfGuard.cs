using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace HostsGuard.Service;

/// <summary>
/// SSRF guard for client-supplied list URLs. The service runs as LocalSystem,
/// so a blocklist/allowlist URL a low-privilege caller supplies must not be
/// allowed to make the service reach loopback, private, link-local, CGNAT, ULA,
/// or cloud-metadata endpoints. Requires https and re-validates every resolved
/// address of the host (redirects are disabled separately in the handler).
/// </summary>
public static class SsrfGuard
{
    /// <summary>Validate scheme + resolve host; throws <see cref="SsrfBlockedException"/> on a non-public target.</summary>
    public static async Task EnsurePublicHttpsAsync(string url, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new SsrfBlockedException($"'{url}' is not an absolute https URL");
        }

        IPAddress[] addresses;
        if (IPAddress.TryParse(uri.Host, out var literal))
        {
            addresses = new[] { literal };
        }
        else
        {
            try
            {
                addresses = await Dns.GetHostAddressesAsync(uri.Host, ct);
            }
            catch (SocketException ex)
            {
                throw new SsrfBlockedException($"could not resolve '{uri.Host}': {ex.Message}");
            }
        }

        if (addresses.Length == 0)
        {
            throw new SsrfBlockedException($"'{uri.Host}' resolved to no addresses");
        }

        foreach (var address in addresses)
        {
            if (!IsPublic(address))
            {
                throw new SsrfBlockedException($"'{uri.Host}' resolves to a non-public address ({address})");
            }
        }
    }

    /// <summary>True if <paramref name="address"/> is a routable public address (SSRF-safe).</summary>
    public static bool IsPublic(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b switch
            {
                [10, ..] => false,                          // 10.0.0.0/8
                [172, >= 16 and <= 31, ..] => false,        // 172.16.0.0/12
                [192, 168, ..] => false,                    // 192.168.0.0/16
                [169, 254, ..] => false,                    // 169.254.0.0/16 link-local (+ metadata)
                [100, >= 64 and <= 127, ..] => false,       // 100.64.0.0/10 CGNAT
                [127, ..] => false,                         // loopback
                [0, ..] => false,                           // 0.0.0.0/8
                [>= 224, ..] => false,                      // multicast/reserved
                _ => true,
            };
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast)
            {
                return false;
            }

            var b = address.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC)
            {
                return false; // fc00::/7 unique local
            }

            return true;
        }

        return false;
    }

    /// <summary>
    /// Resolve the target host at connect time, drop every non-public address,
    /// and open the socket only to a surviving public IP. This closes the
    /// resolve-then-connect DNS-rebinding window for LocalSystem-owned egress.
    /// </summary>
    public static async ValueTask<Stream> ConnectToPublicOnlyAsync(
        SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var host = context.DnsEndPoint.Host;
        IPAddress[] resolved = IPAddress.TryParse(host, out var literal)
            ? new[] { literal }
            : await Dns.GetHostAddressesAsync(host, ct);

        var publicAddresses = PublicAddressesOrThrow(host, resolved);

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(publicAddresses, context.DnsEndPoint.Port, ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Keep only public addresses from a connect-time resolution, or throw if
    /// none survive.
    /// </summary>
    public static IPAddress[] PublicAddressesOrThrow(string host, IPAddress[] resolved)
    {
        var publicAddresses = Array.FindAll(resolved, IsPublic);
        if (publicAddresses.Length == 0)
        {
            throw new SsrfBlockedException(
                $"'{host}' resolved to no public address at connect time");
        }

        return publicAddresses;
    }
}

/// <summary>Raised when a client-supplied URL targets a non-public destination.</summary>
public sealed class SsrfBlockedException : Exception
{
    public SsrfBlockedException(string message) : base(message)
    {
    }
}
