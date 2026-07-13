using System.Net;
using System.Net.Http;

namespace HostsGuard.Service;

/// <summary>Remote list fetch seam so import logic is testable offline.</summary>
public interface IListFetcher
{
    /// <summary>Fetch a text list, enforcing a hard byte cap while streaming.</summary>
    Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct);

    /// <summary>
    /// Consume a text response without requiring one full payload string. Test
    /// fakes keep working through this default buffered adapter; the production
    /// HTTP fetcher overrides it with a byte-limited streaming reader.
    /// </summary>
    async Task<T> ReadTextAsync<T>(
        string url,
        int maxBytes,
        Func<TextReader, CancellationToken, Task<T>> consume,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(consume);
        using var reader = new StringReader(await FetchAsync(url, maxBytes, ct));
        // Preserve the legacy fake/custom-fetcher contract: once a buffered
        // FetchAsync implementation has accepted and returned a payload, finish
        // parsing it even if owner shutdown raced the return. The production
        // HttpListFetcher override remains cooperatively cancellable while the
        // network stream is being read.
        return await consume(reader, CancellationToken.None);
    }

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
            ConnectCallback = SsrfGuard.ConnectToPublicOnlyAsync,
        };
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("HostsGuard/1.0");
    }

    public async Task<string> FetchAsync(string url, int maxBytes, CancellationToken ct)
        => System.Text.Encoding.UTF8.GetString(await FetchBytesAsync(url, maxBytes, ct));

    public async Task<T> ReadTextAsync<T>(
        string url,
        int maxBytes,
        Func<TextReader, CancellationToken, Task<T>> consume,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(consume);
        await SsrfGuard.EnsurePublicHttpsAsync(url, ct);
        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        ValidateResponse(url, response);
        await using var responseStream = await response.Content.ReadAsStreamAsync(ct);
        await using var limited = new LimitedReadStream(responseStream, maxBytes, url);
        using var reader = new StreamReader(
            limited,
            System.Text.Encoding.UTF8,
            detectEncodingFromByteOrderMarks: true,
            bufferSize: 65536,
            leaveOpen: true);
        return await consume(reader, ct);
    }

    public async Task<byte[]> FetchBytesAsync(string url, int maxBytes, CancellationToken ct)
    {
        // Every real egress passes here — validate the target is public https
        // before the LocalSystem service issues the request (SSRF guard).
        await SsrfGuard.EnsurePublicHttpsAsync(url, ct);

        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        ValidateResponse(url, response);

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

    private static void ValidateResponse(string url, HttpResponseMessage response)
    {
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new InvalidOperationException($"list at {url} redirected ({(int)response.StatusCode}); refusing to follow");
        }

        response.EnsureSuccessStatusCode();
    }

    private sealed class LimitedReadStream(Stream inner, int maxBytes, string url) : Stream
    {
        private long _read;

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => _read;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = inner.Read(buffer, offset, count);
            Account(read);
            return read;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var read = await inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
            Account(read);
            return read;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await inner.ReadAsync(buffer, cancellationToken);
            Account(read);
            return read;
        }

        private void Account(int read)
        {
            _read += read;
            if (_read > maxBytes)
            {
                throw new InvalidOperationException($"list at {url} exceeds {maxBytes} bytes");
            }
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>
    /// Keep only public addresses from a connect-time resolution, or throw if
    /// none survive. Extracted so the DNS-rebinding defense is unit-testable
    /// without a live socket.
    /// </summary>
    public static IPAddress[] PublicAddressesOrThrow(string host, IPAddress[] resolved)
        => SsrfGuard.PublicAddressesOrThrow(host, resolved);

    public void Dispose() => _http.Dispose();
}
