using FluentAssertions;
using HostsGuard.App.ViewModels;
using HostsGuard.Contracts;
using Xunit;

namespace HostsGuard.App.Tests;

public sealed class ResolverHealthSurfaceTests
{
    [Fact]
    public void Row_preserves_adapter_endpoint_protocol_and_exact_probe_evidence()
    {
        var row = ResolverHealthRowViewModel.From(new ResolverHealthEntry
        {
            AdapterId = "{adapter-guid}",
            AdapterName = "Ethernet",
            Endpoint = "1.1.1.1",
            Protocol = "udp",
            AStatus = "available",
            ACount = 2,
            AaaaStatus = "unavailable",
            AaaaDetail = "No AAAA response",
            RttAvailable = true,
            RttMs = 18,
            TlsStatus = "not_applicable",
            Success = true,
        });

        row.Adapter.Should().Be("Ethernet");
        row.Endpoint.Should().Be("1.1.1.1");
        row.Protocol.Should().Be("UDP");
        row.AResult.Should().Be("Available (2)");
        row.AaaaResult.Should().Be("No AAAA response");
        row.RttText.Should().Be("18 ms");
        row.TlsStatus.Should().Be("Not applicable");
        row.CertificateStatus.Should().Be("Not applicable");
        row.ResultText.Should().Be("Healthy");
    }

    [Fact]
    public void Row_labels_unavailable_metrics_and_certificate_failures_without_guessing()
    {
        var row = ResolverHealthRowViewModel.From(new ResolverHealthEntry
        {
            AdapterName = "Wi-Fi",
            Endpoint = "https://dns.example/dns-query",
            Protocol = "doh",
            AStatus = "failed",
            AaaaStatus = "unavailable",
            RttAvailable = false,
            TlsStatus = "certificate_failure",
            Error = "certificate name mismatch",
            Success = false,
        });

        row.Protocol.Should().Be("DOH");
        row.AResult.Should().Be("Failed");
        row.AaaaResult.Should().Be("Unavailable");
        row.RttText.Should().Be("Unavailable");
        row.TlsStatus.Should().Be("Certificate failure");
        row.CertificateStatus.Should().Be("Failed");
        row.ResultText.Should().Be("certificate name mismatch");
    }
}
