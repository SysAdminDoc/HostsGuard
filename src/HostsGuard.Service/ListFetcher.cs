using System.Net.Http;

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
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
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

    public void Dispose() => _http.Dispose();
}
