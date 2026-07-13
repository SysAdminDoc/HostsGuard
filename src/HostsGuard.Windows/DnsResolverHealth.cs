using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace HostsGuard.Windows;

public enum DnsResolverProtocol
{
    Unavailable,
    Udp,
    Doh,
}

public enum DnsResolverProbeStatus
{
    Available,
    Unavailable,
    Failed,
}

public enum DnsResolverTlsStatus
{
    NotApplicable,
    Valid,
    CertificateFailure,
    TlsFailure,
    Unavailable,
}

public sealed record DnsResolverAddressResult(
    DnsResolverProbeStatus Status,
    int Count,
    string Detail);

/// <summary>One read-only resolver-health observation for one adapter and endpoint.</summary>
public sealed record DnsResolverHealthResult(
    string AdapterId,
    string AdapterName,
    string ResolverEndpoint,
    DnsResolverProtocol Protocol,
    DnsResolverAddressResult Ipv4,
    DnsResolverAddressResult Ipv6,
    TimeSpan? RoundTrip,
    DnsResolverTlsStatus TlsStatus,
    string Error);

internal sealed record DnsResolverHealthTarget(
    string AdapterId,
    string AdapterName,
    IPAddress ResolverAddress,
    DnsResolverProtocol Protocol,
    Uri? DohTemplate,
    IPAddress? LocalAddress = null)
{
    public string Endpoint => Protocol switch
    {
        DnsResolverProtocol.Doh => DohTemplate?.AbsoluteUri ?? ResolverAddress.ToString(),
        DnsResolverProtocol.Udp => ResolverAddress.ToString(),
        _ => "unavailable",
    };
}

internal sealed record DnsResolverTransportResult(
    DnsResolverAddressResult Ipv4,
    DnsResolverAddressResult Ipv6,
    TimeSpan? RoundTrip,
    DnsResolverTlsStatus TlsStatus,
    string Error);

internal interface IDnsResolverHealthTransport
{
    Task<DnsResolverTransportResult> ProbeAsync(
        DnsResolverHealthTarget target,
        string host,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

internal interface IDnsResolverHealthTargetSource
{
    IReadOnlyList<DnsResolverHealthTarget> GetTargets(IReadOnlyList<DnsAdapterState> adapters);
}

/// <summary>
/// Bounded, read-only resolver health checks. The engine never changes adapter or
/// DNS settings and is safe to call manually or from a non-overlapping scheduler.
/// </summary>
internal sealed class DnsResolverHealthProbe(
    IDnsResolverHealthTargetSource targetSource,
    IDnsResolverHealthTransport transport)
{
    private const int MaxTargets = 32;
    private const int MaxConcurrency = 4;

    public async Task<IReadOnlyList<DnsResolverHealthResult>> CheckAsync(
        IReadOnlyList<DnsAdapterState> adapters,
        string host,
        TimeSpan perProbeTimeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (perProbeTimeout <= TimeSpan.Zero || perProbeTimeout > TimeSpan.FromSeconds(10))
        {
            throw new ArgumentOutOfRangeException(nameof(perProbeTimeout), "Probe timeout must be between zero and ten seconds.");
        }

        var targets = targetSource.GetTargets(adapters)
            .Take(MaxTargets)
            .ToArray();
        using var concurrency = new SemaphoreSlim(MaxConcurrency, MaxConcurrency);
        var checks = targets.Select(async target =>
        {
            await concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var result = await transport.ProbeAsync(target, host.Trim(), perProbeTimeout, cancellationToken)
                    .ConfigureAwait(false);
                return new DnsResolverHealthResult(
                    target.AdapterId,
                    target.AdapterName,
                    target.Endpoint,
                    target.Protocol,
                    result.Ipv4,
                    result.Ipv6,
                    result.RoundTrip,
                    result.TlsStatus,
                    result.Error);
            }
            finally
            {
                concurrency.Release();
            }
        });

        return (await Task.WhenAll(checks).ConfigureAwait(false))
            .OrderBy(result => result.AdapterName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(result => result.ResolverEndpoint, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsDnsResolverHealthTargetSource : IDnsResolverHealthTargetSource
{
    private const string InterfaceParameters =
        @"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters";

    private readonly Func<string, IPAddress, Uri?> _readDohTemplate;
    private readonly Func<string, AddressFamily, IPAddress?> _findLocalAddress;

    public WindowsDnsResolverHealthTargetSource()
        : this(ReadDohTemplate, FindLocalAddress)
    {
    }

    internal WindowsDnsResolverHealthTargetSource(
        Func<string, IPAddress, Uri?> readDohTemplate,
        Func<string, AddressFamily, IPAddress?>? findLocalAddress = null)
    {
        _readDohTemplate = readDohTemplate;
        _findLocalAddress = findLocalAddress ?? ((_, _) => null);
    }

    public IReadOnlyList<DnsResolverHealthTarget> GetTargets(IReadOnlyList<DnsAdapterState> adapters)
    {
        var targets = new List<DnsResolverHealthTarget>();
        foreach (var adapter in adapters)
        {
            var resolvers = adapter.EffectiveResolvers.Count != 0
                ? adapter.EffectiveResolvers
                : adapter.ConfiguredResolvers;
            if (resolvers.Count == 0)
            {
                targets.Add(new DnsResolverHealthTarget(
                    adapter.Id,
                    adapter.Name,
                    IPAddress.None,
                    DnsResolverProtocol.Unavailable,
                    null));
                continue;
            }

            foreach (var resolverText in resolvers.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!IPAddress.TryParse(resolverText, out var resolver))
                {
                    continue;
                }

                var template = _readDohTemplate(adapter.Id, resolver);
                targets.Add(new DnsResolverHealthTarget(
                    adapter.Id,
                    adapter.Name,
                    resolver,
                    template is null ? DnsResolverProtocol.Udp : DnsResolverProtocol.Doh,
                    template,
                    _findLocalAddress(adapter.Id, resolver.AddressFamily)));
            }
        }

        return targets;
    }

    private static Uri? ReadDohTemplate(string adapterId, IPAddress resolver)
    {
        try
        {
            var family = resolver.AddressFamily == AddressFamily.InterNetworkV6 ? "Doh6" : "Doh";
            var path = $@"{InterfaceParameters}\{adapterId}\DohInterfaceSettings\{family}\{resolver}";
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return NormalizeDohTemplate(key?.GetValue("DohTemplate") as string);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    internal static Uri? NormalizeDohTemplate(string? raw)
    {
        var endpoint = raw?.Trim().Replace("{?dns}", string.Empty, StringComparison.Ordinal);
        return Uri.TryCreate(endpoint, UriKind.Absolute, out var template) &&
               template.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            ? template
            : null;
    }

    private static IPAddress? FindLocalAddress(string adapterId, AddressFamily family)
    {
        try
        {
            var adapter = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(candidate => string.Equals(candidate.Id, adapterId, StringComparison.OrdinalIgnoreCase));
            return adapter?.GetIPProperties().UnicastAddresses
                .Select(address => address.Address)
                .FirstOrDefault(address => address.AddressFamily == family);
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }
}

internal sealed class SystemDnsResolverHealthTransport : IDnsResolverHealthTransport
{
    private const ushort A = 1;
    private const ushort Aaaa = 28;

    public async Task<DnsResolverTransportResult> ProbeAsync(
        DnsResolverHealthTarget target,
        string host,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (target.Protocol == DnsResolverProtocol.Unavailable)
        {
            var unavailable = new DnsResolverAddressResult(DnsResolverProbeStatus.Unavailable, 0, "unavailable");
            return new DnsResolverTransportResult(
                unavailable,
                unavailable,
                null,
                DnsResolverTlsStatus.Unavailable,
                "resolver_endpoint_unavailable");
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var timer = Stopwatch.StartNew();
        try
        {
            var probes = target.Protocol == DnsResolverProtocol.Doh
                ? await ProbeDohAsync(target, host, deadline.Token).ConfigureAwait(false)
                : await ProbeUdpAsync(target, host, deadline.Token).ConfigureAwait(false);
            timer.Stop();
            return new DnsResolverTransportResult(
                probes.Ipv4,
                probes.Ipv6,
                timer.Elapsed,
                target.Protocol == DnsResolverProtocol.Doh
                    ? DnsResolverTlsStatus.Valid
                    : DnsResolverTlsStatus.NotApplicable,
                string.Empty);
        }
        catch (ResolverCertificateException ex)
        {
            timer.Stop();
            return Failure(timer.Elapsed, DnsResolverTlsStatus.CertificateFailure, "certificate_failure", ex.GetType().Name);
        }
        catch (HttpRequestException ex) when (ex.HttpRequestError == HttpRequestError.SecureConnectionError)
        {
            timer.Stop();
            return Failure(timer.Elapsed, DnsResolverTlsStatus.TlsFailure, "tls_failure", ex.GetType().Name);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            timer.Stop();
            return Failure(
                timer.Elapsed,
                target.Protocol == DnsResolverProtocol.Doh ? DnsResolverTlsStatus.Unavailable : DnsResolverTlsStatus.NotApplicable,
                "timeout",
                "timeout");
        }
        catch (Exception ex) when (ex is SocketException or HttpRequestException or IOException or InvalidDataException)
        {
            timer.Stop();
            return Failure(
                timer.Elapsed,
                target.Protocol == DnsResolverProtocol.Doh ? DnsResolverTlsStatus.Unavailable : DnsResolverTlsStatus.NotApplicable,
                "transport_failure",
                ex.GetType().Name);
        }
    }

    private static DnsResolverTransportResult Failure(
        TimeSpan elapsed,
        DnsResolverTlsStatus tlsStatus,
        string error,
        string detail)
    {
        var unavailable = new DnsResolverAddressResult(DnsResolverProbeStatus.Unavailable, 0, detail);
        return new DnsResolverTransportResult(unavailable, unavailable, elapsed, tlsStatus, error);
    }

    private static async Task<(DnsResolverAddressResult Ipv4, DnsResolverAddressResult Ipv6)> ProbeUdpAsync(
        DnsResolverHealthTarget target,
        string host,
        CancellationToken cancellationToken)
    {
        var v4 = QueryUdpAsync(target.ResolverAddress, target.LocalAddress, host, A, cancellationToken);
        var v6 = QueryUdpAsync(target.ResolverAddress, target.LocalAddress, host, Aaaa, cancellationToken);
        await Task.WhenAll(v4, v6).ConfigureAwait(false);
        return (await v4.ConfigureAwait(false), await v6.ConfigureAwait(false));
    }

    private static async Task<DnsResolverAddressResult> QueryUdpAsync(
        IPAddress resolver,
        IPAddress? localAddress,
        string host,
        ushort queryType,
        CancellationToken cancellationToken)
    {
        var query = BuildQuery(host, queryType);
        using var client = new UdpClient(resolver.AddressFamily);
        if (localAddress is not null)
        {
            client.Client.Bind(new IPEndPoint(localAddress, 0));
        }

        client.Connect(new IPEndPoint(resolver, 53));
        await client.SendAsync(query, cancellationToken).ConfigureAwait(false);
        var response = await client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        return ParseResponse(query, response.Buffer, queryType);
    }

    private static async Task<(DnsResolverAddressResult Ipv4, DnsResolverAddressResult Ipv6)> ProbeDohAsync(
        DnsResolverHealthTarget target,
        string host,
        CancellationToken cancellationToken)
    {
        if (target.DohTemplate is null)
        {
            throw new InvalidDataException("DoH template unavailable.");
        }

        var certificateFailure = 0;
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, errors) =>
                {
                    if (errors == SslPolicyErrors.None)
                    {
                        return true;
                    }

                    Interlocked.Exchange(ref certificateFailure, 1);
                    return false;
                },
            },
            ConnectCallback = async (_, token) =>
            {
                var socket = new Socket(target.ResolverAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    if (target.LocalAddress is not null)
                    {
                        socket.Bind(new IPEndPoint(target.LocalAddress, 0));
                    }

                    await socket.ConnectAsync(new IPEndPoint(target.ResolverAddress, target.DohTemplate.Port), token)
                        .ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        try
        {
            var v4 = QueryDohAsync(client, target.DohTemplate, host, A, cancellationToken);
            var v6 = QueryDohAsync(client, target.DohTemplate, host, Aaaa, cancellationToken);
            await Task.WhenAll(v4, v6).ConfigureAwait(false);
            return (await v4.ConfigureAwait(false), await v6.ConfigureAwait(false));
        }
        catch (HttpRequestException ex) when (Volatile.Read(ref certificateFailure) != 0)
        {
            throw new ResolverCertificateException("DoH certificate validation failed.", ex);
        }
    }

    private static async Task<DnsResolverAddressResult> QueryDohAsync(
        HttpClient client,
        Uri endpoint,
        string host,
        ushort queryType,
        CancellationToken cancellationToken)
    {
        var query = BuildQuery(host, queryType);
        using var content = new ByteArrayContent(query);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = content };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (payload.Length > 65_535)
        {
            throw new InvalidDataException("Oversized DNS response.");
        }

        return ParseResponse(query, payload, queryType);
    }

    internal static byte[] BuildQuery(string host, ushort queryType)
    {
        var ascii = new IdnMapping().GetAscii(host.Trim().TrimEnd('.'));
        if (ascii.Length is 0 or > 253)
        {
            throw new ArgumentException("Invalid DNS probe host.", nameof(host));
        }
        var labels = ascii.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length == 0 || labels.Any(label => label.Length is 0 or > 63))
        {
            throw new ArgumentException("Invalid DNS probe host.", nameof(host));
        }

        var length = 12 + labels.Sum(label => 1 + label.Length) + 1 + 4;
        var buffer = new byte[length];
        RandomNumberGenerator.Fill(buffer.AsSpan(0, 2));
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4, 2), 1);
        var offset = 12;
        foreach (var label in labels)
        {
            buffer[offset++] = (byte)label.Length;
            foreach (var c in label)
            {
                buffer[offset++] = (byte)c;
            }
        }

        buffer[offset++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset, 2), queryType);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 2, 2), 1);
        return buffer;
    }

    internal static DnsResolverAddressResult ParseResponse(byte[] query, byte[] response, ushort queryType)
    {
        if (response.Length < 12 || !response.AsSpan(0, 2).SequenceEqual(query.AsSpan(0, 2)))
        {
            throw new InvalidDataException("Invalid DNS response.");
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2, 2));
        if ((flags & 0x8000) == 0)
        {
            throw new InvalidDataException("DNS payload is not a response.");
        }

        if ((flags & 0x0200) != 0)
        {
            return new DnsResolverAddressResult(DnsResolverProbeStatus.Failed, 0, "truncated");
        }

        var rcode = flags & 0x000F;
        if (rcode != 0)
        {
            return new DnsResolverAddressResult(DnsResolverProbeStatus.Failed, 0, $"rcode_{rcode}");
        }

        var questions = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(4, 2));
        var answers = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6, 2));
        var offset = 12;
        for (var i = 0; i < questions; i++)
        {
            SkipName(response, ref offset);
            EnsureAvailable(response, offset, 4);
            offset += 4;
        }

        var count = 0;
        for (var i = 0; i < answers; i++)
        {
            SkipName(response, ref offset);
            EnsureAvailable(response, offset, 10);
            var type = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset, 2));
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset + 8, 2));
            offset += 10;
            EnsureAvailable(response, offset, dataLength);
            if (type == queryType && ((queryType == A && dataLength == 4) || (queryType == Aaaa && dataLength == 16)))
            {
                count++;
            }

            offset += dataLength;
        }

        return new DnsResolverAddressResult(
            DnsResolverProbeStatus.Available,
            count,
            count == 0 ? "no_records" : "resolved");
    }

    private static void SkipName(byte[] response, ref int offset)
    {
        var labels = 0;
        while (true)
        {
            EnsureAvailable(response, offset, 1);
            var length = response[offset++];
            if (length == 0)
            {
                return;
            }

            if ((length & 0xC0) == 0xC0)
            {
                EnsureAvailable(response, offset, 1);
                offset++;
                return;
            }

            if (length > 63 || ++labels > 127)
            {
                throw new InvalidDataException("Invalid DNS name.");
            }

            EnsureAvailable(response, offset, length);
            offset += length;
        }
    }

    private static void EnsureAvailable(byte[] response, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > response.Length - length)
        {
            throw new InvalidDataException("Truncated DNS response.");
        }
    }

    private sealed class ResolverCertificateException(string message, Exception innerException)
        : AuthenticationException(message, innerException);
}
