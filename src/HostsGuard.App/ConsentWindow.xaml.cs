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

        _deadline = DateTime.UtcNow + DecisionWindow;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        Tick();
        Closed += (_, _) => _timer.Stop();
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

    private void Decide(string verdict, bool permanent)
    {
        Result = new ConnectionDecision
        {
            Id = _request.Id,
            Application = _request.Application,
            Direction = _request.Direction,
            RemoteAddress = _request.RemoteAddress,
            Protocol = _request.Protocol,
            Verdict = verdict,
            Permanent = permanent,
            ScopeRemote = ScopeRemote.IsChecked == true,
        };
        Close();
    }

    private void OnAllowOnce(object sender, RoutedEventArgs e) => Decide("allow", permanent: false);

    private void OnAllowAlways(object sender, RoutedEventArgs e) => Decide("allow", permanent: true);

    private void OnBlockOnce(object sender, RoutedEventArgs e) => Decide("block", permanent: false);

    private void OnBlockAlways(object sender, RoutedEventArgs e) => Decide("block", permanent: true);
}
