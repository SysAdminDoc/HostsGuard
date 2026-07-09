using System.IO;
using System.Windows;
using System.Windows.Threading;
using HostsGuard.Contracts;

namespace HostsGuard.App;

/// <summary>
/// Top-most consent prompt for a blocked connection (WFCP-011). A LocalSystem
/// service cannot raise interactive toasts into the user session — this window
/// is the WFC-style answer. Timeout closes with no decision: default-deny is
/// already holding the connection, so "no answer" safely stays blocked.
/// </summary>
public partial class ConsentWindow : Window
{
    private static readonly TimeSpan DecisionWindow = TimeSpan.FromSeconds(55);

    private readonly ConnectionDecisionRequest _request;
    private readonly DispatcherTimer _timer;
    private DateTime _deadline;

    public ConsentWindow(ConnectionDecisionRequest request)
    {
        _request = request ?? throw new ArgumentNullException(nameof(request));
        InitializeComponent();

        AppName.Text = request.CommandLine.Length != 0 ? request.CommandLine : Path.GetFileName(request.Application);
        AppPath.Text = request.Application;
        RemoteText.Text = $"{request.RemoteAddress}:{request.RemotePort} ({request.Protocol})";
        DirectionText.Text = request.Direction == "In"
            ? Services.I18n.T("Consent_Inbound", "Inbound")
            : Services.I18n.T("Consent_Outbound", "Outbound");
        PidText.Text = request.ProcessId > 0
            ? Services.I18n.T("Consent_Pid", "PID {0}", request.ProcessId)
            : Services.I18n.T("Consent_PidUnknown", "unknown PID");
        ScopeRemote.Content = Services.I18n.T("Consent_ScopeRemote", "Apply only to {0}", request.RemoteAddress);

        // NET-066 decision-quality enrichment.
        CountryText.Text = request.Country.Length != 0
            ? request.Country
            : Services.I18n.T("Consent_CountryUnknown", "unknown");
        SignerText.Text = request.Signer.Length != 0
            ? request.Signer
            : Services.I18n.T("Consent_SignerUnknown", "unsigned / unknown");
        ThreatBanner.Visibility = request.Threat ? Visibility.Visible : Visibility.Collapsed;

        // NET-113: offer trust-by-publisher only when the binary is signed.
        var publisher = HostsGuard.Core.PublisherName.Of(request.Signer);
        if (publisher.Length != 0)
        {
            TrustPublisher.Content = Services.I18n.T("Consent_TrustPublisher", "Trust all software signed by \"{0}\"", publisher);
            TrustPublisher.Visibility = Visibility.Visible;
        }

        // NET-117: offer trust-by-folder when the app has a resolvable parent dir.
        var folder = HostsGuard.Core.PathScope.ParentFolder(request.Application);
        if (folder.Length != 0)
        {
            TrustFolder.Content = Services.I18n.T("Consent_TrustFolder", "Trust all software in \"{0}\"", folder);
            TrustFolder.Visibility = Visibility.Visible;
        }

        // svchost attribution (NET-073): show the owning service; offer the
        // per-service scope only when it's unambiguous (one service, known key).
        if (request.Service.Length != 0)
        {
            ServiceLabel.Visibility = ServiceText.Visibility = Visibility.Visible;
            ServiceText.Text = request.Service;
        }

        if (request.ServiceKey.Length != 0)
        {
            ScopeService.Visibility = Visibility.Visible;
            ScopeService.Content = Services.I18n.T("Consent_ScopeService", "Only the '{0}' service", request.ServiceKey);
        }

        if (request.CommandLine.Length != 0 && request.ScriptBindingKey.Length != 0)
        {
            CommandLineLabel.Visibility = CommandLineText.Visibility = Visibility.Visible;
            CommandLineText.Text = request.CommandLine;
            ScopeCommandLine.Visibility = Visibility.Visible;
            ScopeCommandLine.IsChecked = true;
        }

        _ = ResolveHostAsync(request.RemoteAddress);

        _deadline = DateTime.UtcNow + DecisionWindow;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
        // Land keyboard/screen-reader focus on the primary action (NET-080).
        Loaded += (_, _) => AllowButton.Focus();
        Closed += (_, _) => _timer.Stop();
    }

    /// <summary>Best-effort reverse-DNS for the remote IP, resolved off-thread so the prompt never blocks.</summary>
    private async Task ResolveHostAsync(string remote)
    {
        if (!System.Net.IPAddress.TryParse(remote, out var ip))
        {
            HostText.Text = "—";
            return;
        }

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var entry = await System.Net.Dns.GetHostEntryAsync(ip).WaitAsync(cts.Token);
            if (string.IsNullOrEmpty(entry.HostName) || entry.HostName == remote)
            {
                HostText.Text = Services.I18n.T("Consent_NoPtr", "no PTR record");
            }
            else
            {
                // Annotate with the curated purpose when known (NET-078).
                var purpose = HostsGuard.Core.DomainPurpose.Lookup(entry.HostName);
                HostText.Text = purpose.Length != 0 ? $"{entry.HostName}  ·  {purpose}" : entry.HostName;
            }
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or OperationCanceledException or TimeoutException or ArgumentException)
        {
            HostText.Text = Services.I18n.T("Consent_NoPtr", "no PTR record");
        }
    }

    /// <summary>The user's decision; null when dismissed or timed out (stays blocked).</summary>
    public ConnectionDecision? Result { get; private set; }

    private void Tick()
    {
        var left = _deadline - DateTime.UtcNow;
        if (left <= TimeSpan.Zero)
        {
            Close(); // no decision — default-deny keeps it blocked
            return;
        }

        Countdown.Text = Services.I18n.T("Consent_Countdown", "closes in {0:0} s", left.TotalSeconds);
    }

    private void Decide(string verdict)
    {
        Result = new ConnectionDecision
        {
            Id = _request.Id,
            Application = _request.Application,
            Direction = _request.Direction,
            RemoteAddress = _request.RemoteAddress,
            Protocol = _request.Protocol,
            RemotePort = _request.RemotePort,
            Verdict = verdict,
            ScopeRemote = ScopeRemote.IsChecked == true,
            ScopePort = ScopePort.IsChecked == true,
            ScopeProtocol = ScopeProtocol.IsChecked == true,
            ScopeService = ScopeService.IsChecked == true,
            ServiceKey = _request.ServiceKey,
            ScopeCommandLine = ScopeCommandLine.IsChecked == true,
            CommandLine = _request.CommandLine,
            ScriptPath = _request.ScriptPath,
            ScriptBindingKey = _request.ScriptBindingKey,
            Duration = SelectedDuration(),
            TrustPublisher = TrustPublisher.IsChecked == true,
            TrustFolder = TrustFolder.IsChecked == true,
        };
        Close();
    }

    private string SelectedDuration()
        => (DurationBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag as string ?? "always";

    private void OnAllow(object sender, RoutedEventArgs e) => Decide("allow");

    private void OnBlock(object sender, RoutedEventArgs e) => Decide("block");

    private void OnAllowAll(object sender, RoutedEventArgs e) => DecideAll("allow");

    private void OnBlockAll(object sender, RoutedEventArgs e) => DecideAll("block");

    /// <summary>NET-099: answer every pending prompt from this app with one verdict.</summary>
    private void DecideAll(string verdict)
    {
        Result = new ConnectionDecision
        {
            Id = _request.Id,
            Application = _request.Application,
            Direction = _request.Direction,
            RemoteAddress = _request.RemoteAddress,
            Protocol = _request.Protocol,
            RemotePort = _request.RemotePort,
            Verdict = verdict,
            Duration = "always",
            ApplyToApp = true,
        };
        Close();
    }

    /// <summary>Open a reputation lookup for the process on VirusTotal (NET-085).</summary>
    private void OnLookup(object sender, RoutedEventArgs e)
    {
        var name = Path.GetFileName(_request.Application);
        var query = name.Length != 0 ? name : _request.RemoteAddress;
        if (query.Length != 0)
        {
            Services.Research.Open("https://www.virustotal.com/gui/search/{d}", query);
        }
    }
}
