using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public sealed class DnsPrivacyPostureTests
{
    [Fact]
    public void Ech_observations_take_precedence_over_cache_guessing()
    {
        var result = DnsPrivacyPosture.Evaluate(new DnsPrivacySignals(
            HttpsRecords: 2,
            SvcbRecords: 1,
            SniCaptureActive: true,
            EchUnavailableObservations: 3,
            DnsEncryptedOnly: false,
            DohBlockingActive: false,
            QuicBlocked: false));

        result.State.Should().Be(DnsPrivacyPosture.StateEchHidden);
        result.EchUnavailableObserved.Should().BeTrue();
        result.EchUnobservable.Should().BeFalse();
        result.Summary.Should().Contain("3 TLS ClientHello");
        result.Remediation.Should().Contain("No DNS or firewall blocking is changed automatically");
    }

    [Fact]
    public void Service_binding_cache_without_sni_capture_is_unobservable()
    {
        var result = DnsPrivacyPosture.Evaluate(new DnsPrivacySignals(
            HttpsRecords: 1,
            SvcbRecords: 0,
            SniCaptureActive: false,
            EchUnavailableObservations: 0,
            DnsEncryptedOnly: true,
            DohBlockingActive: false,
            QuicBlocked: true));

        result.State.Should().Be(DnsPrivacyPosture.StateUnobservable);
        result.ServiceBindingObserved.Should().BeTrue();
        result.EchUnobservable.Should().BeTrue();
        result.Summary.Should().Contain("1 HTTPS");
        result.Remediation.Should().Contain("requires encrypted DNS");
        result.Remediation.Should().Contain("does not change DoH or QUIC blocking unless you enable those controls");
    }
}
