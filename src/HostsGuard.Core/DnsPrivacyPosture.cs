namespace HostsGuard.Core;

/// <summary>Inputs used to explain modern DNS/TLS name-visibility posture.</summary>
public sealed record DnsPrivacySignals(
    int HttpsRecords,
    int SvcbRecords,
    bool SniCaptureActive,
    int EchUnavailableObservations,
    bool DnsEncryptedOnly,
    bool DohBlockingActive,
    bool QuicBlocked);

/// <summary>Human-facing posture for HTTPS/SVCB DNS records and ECH visibility.</summary>
public sealed record DnsPrivacyPostureResult(
    string State,
    string Summary,
    string Remediation,
    bool ServiceBindingObserved,
    bool EchUnavailableObserved,
    bool EchUnobservable);

public static class DnsPrivacyPosture
{
    public const string StateEchHidden = "ech-hidden";
    public const string StateUnobservable = "unobservable";
    public const string StateServiceBindingObserved = "service-binding-observed";
    public const string StateNoServiceBindingObserved = "no-service-binding-observed";

    public static DnsPrivacyPostureResult Evaluate(DnsPrivacySignals signals)
    {
        var serviceBindingObserved = signals.HttpsRecords > 0 || signals.SvcbRecords > 0;
        var serviceBindings = FormatServiceBindingCount(signals.HttpsRecords, signals.SvcbRecords);

        string state;
        string summary;
        string remediation;
        bool unobservable;
        if (signals.EchUnavailableObservations > 0)
        {
            state = StateEchHidden;
            summary = $"{signals.EchUnavailableObservations} TLS ClientHello observation(s) used ECH, so the real SNI was encrypted and unavailable.";
            remediation = "Keep TLS SNI capture on for non-ECH traffic and use Activity IP/domain firewall controls for these flows. No DNS or firewall blocking is changed automatically.";
            unobservable = false;
        }
        else if (!signals.SniCaptureActive)
        {
            state = StateUnobservable;
            summary = serviceBindingObserved
                ? $"{serviceBindings} in the Windows resolver cache, but ECH use is unobservable while TLS SNI capture is off."
                : "ECH posture is unobservable because TLS SNI capture is off and no HTTPS/SVCB cache entry is visible.";
            remediation = "Turn on TLS SNI capture to separate clear SNI from ECH-hidden handshakes without changing blocking defaults.";
            unobservable = true;
        }
        else if (serviceBindingObserved)
        {
            state = StateServiceBindingObserved;
            summary = $"{serviceBindings} in the Windows resolver cache. The cache exposes record type and size, not SVCB parameters, so ECH capability cannot be confirmed from cache alone.";
            remediation = "Reproduce the connection with TLS SNI capture on. Use See everything only when you intentionally want to force browser DNS back to the OS resolver.";
            unobservable = true;
        }
        else
        {
            state = StateNoServiceBindingObserved;
            summary = "No HTTPS/SVCB records are currently visible in the Windows resolver cache, so no ECH bootstrap path has been observed.";
            remediation = "Load DNS cache after reproducing the connection; no blocking change is required.";
            unobservable = true;
        }

        if (signals.DnsEncryptedOnly)
        {
            remediation += " This Windows profile requires encrypted DNS, so avoid blanket DoH blocking unless the active resolver stays exempt.";
        }

        if (!signals.DohBlockingActive || !signals.QuicBlocked)
        {
            remediation += " HostsGuard does not change DoH or QUIC blocking unless you enable those controls.";
        }

        return new DnsPrivacyPostureResult(
            state,
            summary,
            remediation,
            serviceBindingObserved,
            signals.EchUnavailableObservations > 0,
            unobservable);
    }

    private static string FormatServiceBindingCount(int httpsRecords, int svcbRecords)
    {
        var parts = new List<string>(2);
        if (httpsRecords > 0)
        {
            parts.Add($"{httpsRecords} HTTPS");
        }

        if (svcbRecords > 0)
        {
            parts.Add($"{svcbRecords} SVCB");
        }

        return parts.Count == 0
            ? "No HTTPS/SVCB records"
            : string.Join(" and ", parts) + " record(s)";
    }
}
