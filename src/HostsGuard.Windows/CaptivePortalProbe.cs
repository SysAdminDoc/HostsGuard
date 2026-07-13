using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace HostsGuard.Windows;

public enum CaptivePortalState
{
    Clear,
    Suspected,
    Offline,
    Unavailable,
}

public sealed record CaptivePortalProbeResult(
    CaptivePortalState State,
    Uri ProbeUri,
    int HttpStatus,
    bool Redirected,
    string ObservedHost,
    string Detail,
    DateTime CheckedAtUtc);

public interface ICaptivePortalProbe
{
    Task<CaptivePortalProbeResult> CheckAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Bounded, read-only check of the fixed Windows NCSI web probe. Redirects are
/// never followed, response bodies are capped, and the result never changes
/// firewall, hosts, DNS, or proxy configuration.
/// </summary>
public sealed class WindowsNcsiCaptivePortalProbe : ICaptivePortalProbe, IDisposable
{
    public static readonly Uri ProbeUri = new("http://www.msftconnecttest.com/connecttest.txt");
    public const string ExpectedBody = "Microsoft Connect Test";

    private readonly HttpClient _http;
    private readonly Func<bool> _networkAvailable;
    private readonly bool _ownsClient;

    public WindowsNcsiCaptivePortalProbe()
        : this(CreateClient(), NetworkInterface.GetIsNetworkAvailable, ownsClient: true)
    {
    }

    internal WindowsNcsiCaptivePortalProbe(HttpClient http, Func<bool>? networkAvailable = null, bool ownsClient = false)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _networkAvailable = networkAvailable ?? NetworkInterface.GetIsNetworkAvailable;
        _ownsClient = ownsClient;
    }

    public async Task<CaptivePortalProbeResult> CheckAsync(CancellationToken cancellationToken)
    {
        var checkedAt = DateTime.UtcNow;
        if (!_networkAvailable())
        {
            return Result(CaptivePortalState.Offline, detail: "Windows reports no available network.", checkedAt: checkedAt);
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ProbeUri);
            using var response = await _http.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            var status = (int)response.StatusCode;
            if (IsRedirect(response.StatusCode))
            {
                var observedHost = SafeHost(response.Headers.Location);
                return Result(
                    CaptivePortalState.Suspected,
                    status,
                    redirected: true,
                    observedHost,
                    observedHost.Length == 0
                        ? "The Windows connectivity probe was redirected."
                        : $"The Windows connectivity probe was redirected to {observedHost}.",
                    checkedAt);
            }

            var body = await ReadBoundedBodyAsync(response.Content, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.OK && string.Equals(body, ExpectedBody, StringComparison.Ordinal))
            {
                return Result(CaptivePortalState.Clear, status, detail: "The Windows connectivity probe returned its expected response.", checkedAt: checkedAt);
            }

            return Result(
                CaptivePortalState.Suspected,
                status,
                detail: response.StatusCode == HttpStatusCode.OK
                    ? "The Windows connectivity probe returned unexpected content."
                    : $"The Windows connectivity probe returned HTTP {status}.",
                checkedAt: checkedAt);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Result(CaptivePortalState.Unavailable, detail: "The Windows connectivity probe timed out.", checkedAt: checkedAt);
        }
        catch (HttpRequestException ex)
        {
            return Result(CaptivePortalState.Unavailable, detail: $"The Windows connectivity probe failed: {SafeException(ex)}", checkedAt: checkedAt);
        }
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _http.Dispose();
        }
    }

    private static HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            MaxResponseHeadersLength = 16,
            ConnectTimeout = TimeSpan.FromSeconds(3),
        };
        return new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(5) };
    }

    private static async Task<string> ReadBoundedBodyAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var buffer = new byte[Encoding.UTF8.GetByteCount(ExpectedBody) + 2];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }

        return Encoding.UTF8.GetString(buffer, 0, total).TrimEnd('\r', '\n');
    }

    private static bool IsRedirect(HttpStatusCode status) => (int)status is >= 300 and <= 399;

    private static string SafeHost(Uri? location)
    {
        if (location is null || !location.IsAbsoluteUri) return string.Empty;
        return location.Host.Length <= 253 ? location.IdnHost : string.Empty;
    }

    private static string SafeException(HttpRequestException exception)
    {
        var message = exception.HttpRequestError.ToString();
        return exception.StatusCode is { } status ? $"{message} (HTTP {(int)status})" : message;
    }

    private static CaptivePortalProbeResult Result(
        CaptivePortalState state,
        int httpStatus = 0,
        bool redirected = false,
        string observedHost = "",
        string detail = "",
        DateTime? checkedAt = null) =>
        new(state, ProbeUri, httpStatus, redirected, observedHost, detail, checkedAt ?? DateTime.UtcNow);
}
