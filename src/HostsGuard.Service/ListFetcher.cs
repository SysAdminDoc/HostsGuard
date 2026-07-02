using System.Net.Http;

namespace HostsGuard.Service;

/// <summary>Remote list fetch seam so import logic is testable offline.</summary>
public interface IListFetcher
{
    /// <summary>Fetch a text list, enforcing a hard byte cap while streaming.</summary>
    Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct);
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
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("HostsGuard/1.0");
    }

    public async Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct)
    {
        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
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

        return System.Text.Encoding.UTF8.GetString(buffer.ToArray());
    }

    public void Dispose() => _http.Dispose();
}
