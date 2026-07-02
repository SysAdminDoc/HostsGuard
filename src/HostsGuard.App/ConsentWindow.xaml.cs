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

        AppName.Text = Path.GetFileName(request.Application);
        AppPath.Text = request.Application;
        RemoteText.Text = $"{request.RemoteAddress}:{request.RemotePort} ({request.Protocol})";
        DirectionText.Text = request.Direction == "In" ? "Inbound" : "Outbound";
        PidText.Text = request.ProcessId > 0 ? $"PID {request.ProcessId}" : "unknown PID";
        ScopeRemote.Content = $"Apply only to {request.RemoteAddress}";

        // NET-066 decision-quality enrichment.
        CountryText.Text = request.Country.Length != 0 ? request.Country : "unknown";
        SignerText.Text = request.Signer.Length != 0 ? request.Signer : "unsigned / unknown";
        ThreatBanner.Visibility = request.Threat ? Visibility.Visible : Visibility.Collapsed;
        _ = ResolveHostAsync(request.RemoteAddress);

        _deadline = DateTime.UtcNow + DecisionWindow;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
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
            HostText.Text = string.IsNullOrEmpty(entry.HostName) || entry.HostName == remote ? "no PTR record" : entry.HostName;
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or OperationCanceledException or TimeoutException or ArgumentException)
        {
            HostText.Text = "no PTR record";
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

        Countdown.Text = $"closes in {left.TotalSeconds:0} s";
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
            Duration = SelectedDuration(),
        };
        Close();
    }

    private string SelectedDuration()
        => (DurationBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag as string ?? "always";

    private void OnAllow(object sender, RoutedEventArgs e) => Decide("allow");

    private void OnBlock(object sender, RoutedEventArgs e) => Decide("block");
}
