using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace HostsGuard.Service;

/// <summary>Remote list fetch seam so import logic is testable offline.</summary>
public interface IListFetcher
{
    /// <summary>Fetch a text list, enforcing a hard byte cap while streaming.</summary>
    Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct);

    /// <summary>Fetch a binary payload (e.g. a gzipped MMDB), byte-capped while streaming.</summary>
    Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct);
}

/// <summary>
/// HttpClient-backed fetcher with a streaming byte cap — the
/// <c>_read_response_limited</c> equivalent: the cap is enforced while reading,
/// not after, so an oversized (or malicious) source cannot balloon memory.
/// </summary>
public sealed class HttpListFetcher : IListFetcher, IDisposable
{
    private readonly HttpClient _http;

    public HttpListFetcher()
    {
        // Redirects OFF: an https→https 302 could smuggle a fetch to a private
        // host past the SSRF pre-check. Callers validate the URL first.
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            // Close the resolve-then-fetch DNS-rebinding window: the SSRF
            // pre-check resolves the host, but HttpClient would re-resolve for
            // the real connect — a rebinding server could hand the guard a
            // public IP and the socket a private one. Doing the connect
            // ourselves re-validates the resolved addresses and dials only a
            // public one, so the socket can never reach a private/loopback/
            // metadata endpoint regardless of what the second lookup returns.
            ConnectCallback = ConnectToPublicOnlyAsync,
        };
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("HostsGuard/1.0");
    }

    public async Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct)
        => System.Text.Encoding.UTF8.GetString(await FetchBytesAsync(url, maxBytes, ct));

    public async Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct)
    {
        // Every real egress passes here — validate the target is public https
        // before the LocalSystem service issues the request (SSRF guard).
        await SsrfGuard.EnsurePublicHttpsAsync(url, ct);

        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            // A redirect on a client-supplied URL is refused, not chased.
            throw new InvalidOperationException($"list at {url} redirected ({(int)response.StatusCode}); refusing to follow");
        }

        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        var chunk = new byte[65536];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > maxBytes)
            {
                throw new InvalidOperationException($"list at {url} exceeds {maxBytes} bytes");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Resolve the target host at connect time, drop every non-public address,
    /// and open the socket only to a surviving public IP. This is the teeth
    /// behind <see cref="SsrfGuard"/>: validation and the actual dial share one
    /// resolution, so a DNS-rebinding attacker cannot slip a private address in
    /// between the pre-check and the fetch.
    /// </summary>
    private static async ValueTask<Stream> ConnectToPublicOnlyAsync(
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
    /// none survive. Extracted so the DNS-rebinding defense is unit-testable
    /// without a live socket.
    /// </summary>
    public static IPAddress[] PublicAddressesOrThrow(string host, IPAddress[] resolved)
    {
        var publicAddresses = Array.FindAll(resolved, SsrfGuard.IsPublic);
        if (publicAddresses.Length == 0)
        {
            throw new SsrfBlockedException(
                $"'{host}' resolved to no public address at connect time");
        }

        return publicAddresses;
    }

    public void Dispose() => _http.Dispose();
}
